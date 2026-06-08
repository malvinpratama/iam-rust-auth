//! Postgres access for the auth service via sqlx (runtime-checked queries).

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    #[allow(dead_code)]
    pub status: String,
    pub email_verified: bool,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: String,
    pub actor_email: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
pub struct RefreshTokenRow {
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct RoleRow {
    pub id: i64,
    pub name: String,
    pub description: String,
}

#[derive(FromRow)]
pub struct OutboxRow {
    pub id: Uuid,
    pub event_type: String,
    pub payload: String,
}

#[derive(Clone)]
pub struct Repo {
    pub pool: PgPool,
}

impl Repo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, email: &str, password_hash: &str) -> sqlx::Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Create a user and assign a role in one transaction. Used by register + bootstrap.
    pub async fn create_user_with_role(
        &self,
        email: &str,
        password_hash: &str,
        role: &str,
    ) -> sqlx::Result<Uuid> {
        let mut tx = self.pool.begin().await?;
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
        )
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) \
             SELECT $1, r.id FROM roles r WHERE r.name = $2 ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn get_user_by_email(&self, email: &str) -> sqlx::Result<Option<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> sqlx::Result<Option<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn delete_user(&self, id: Uuid) -> sqlx::Result<()> {
        // FK cascade removes user_roles and refresh_tokens.
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Transactional outbox (events written atomically with the change) ──

    /// Create a user + default role + a UserRegistered outbox row in one tx.
    /// The id is supplied so the caller can embed it in the event payload.
    pub async fn create_user_with_role_event(
        &self,
        id: Uuid,
        email: &str,
        password_hash: &str,
        role: &str,
        event_type: &str,
        payload: &str,
    ) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(email)
            .bind(password_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) \
             SELECT $1, r.id FROM roles r WHERE r.name = $2 ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO outbox (aggregate_id, event_type, payload) VALUES ($1, $2, $3::jsonb)")
            .bind(id)
            .bind(event_type)
            .bind(payload)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete a user + a UserDeleted outbox row in one tx.
    pub async fn delete_user_event(
        &self,
        id: Uuid,
        event_type: &str,
        payload: &str,
    ) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO outbox (aggregate_id, event_type, payload) VALUES ($1, $2, $3::jsonb)")
            .bind(id)
            .bind(event_type)
            .bind(payload)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fetch_unpublished_outbox(&self, limit: i64) -> sqlx::Result<Vec<OutboxRow>> {
        sqlx::query_as::<_, OutboxRow>(
            "SELECT id, event_type, payload::text AS payload FROM outbox \
             WHERE published_at IS NULL ORDER BY created_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn mark_outbox_published(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE outbox SET published_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── v0.2: lockout, email verification, password reset, audit ──

    pub async fn increment_login_failure(&self, id: Uuid) -> sqlx::Result<i32> {
        sqlx::query_scalar(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1 RETURNING failed_login_attempts",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn lock_user(&self, id: Uuid, until: DateTime<Utc>) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET locked_until = $2, failed_login_attempts = 0 WHERE id = $1")
            .bind(id)
            .bind(until)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn reset_login_state(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_email_verified(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_password(&self, id: Uuid, hash: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_all_user_refresh_tokens(&self, user_id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_email_verification(&self, token_hash: &str, user_id: Uuid, expires_at: DateTime<Utc>) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO email_verifications (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
            .bind(token_hash).bind(user_id).bind(expires_at)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn consume_email_verification(&self, token_hash: &str) -> sqlx::Result<Option<Uuid>> {
        sqlx::query_scalar(
            "UPDATE email_verifications SET consumed_at = now() \
             WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING user_id",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn create_password_reset(&self, token_hash: &str, user_id: Uuid, expires_at: DateTime<Utc>) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
            .bind(token_hash).bind(user_id).bind(expires_at)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn consume_password_reset(&self, token_hash: &str) -> sqlx::Result<Option<Uuid>> {
        sqlx::query_scalar(
            "UPDATE password_resets SET consumed_at = now() \
             WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING user_id",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn insert_audit(&self, actor_id: &str, actor_email: &str, action: &str, target: &str, detail: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO audit_events (actor_id, actor_email, action, target, detail) VALUES ($1, $2, $3, $4, $5)")
            .bind(actor_id).bind(actor_email).bind(action).bind(target).bind(detail)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_audit(&self, limit: i64) -> sqlx::Result<Vec<AuditRow>> {
        sqlx::query_as::<_, AuditRow>(
            "SELECT id, actor_id, actor_email, action, target, detail, created_at \
             FROM audit_events ORDER BY id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn revoke_access_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_token_revoked(&self, jti: &str) -> sqlx::Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)")
                .bind(jti)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    pub async fn create_refresh_token(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_refresh_token(&self, token_hash: &str) -> sqlx::Result<Option<RefreshTokenRow>> {
        sqlx::query_as::<_, RefreshTokenRow>(
            "SELECT user_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: Uuid) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id \
             WHERE ur.user_id = $1 ORDER BY r.name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_user_permissions(&self, user_id: Uuid) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT DISTINCT p.name FROM user_roles ur \
             JOIN role_permissions rp ON rp.role_id = ur.role_id \
             JOIN permissions p ON p.id = rp.permission_id \
             WHERE ur.user_id = $1 ORDER BY p.name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn role_exists(&self, name: &str) -> sqlx::Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)")
                .bind(name)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    pub async fn assign_role(&self, user_id: Uuid, role_name: &str) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) \
             SELECT $1, r.id FROM roles r WHERE r.name = $2 ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_role(&self, user_id: Uuid, role_name: &str) -> sqlx::Result<()> {
        sqlx::query(
            "DELETE FROM user_roles \
             WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)",
        )
        .bind(user_id)
        .bind(role_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_role(&self, name: &str, description: &str) -> sqlx::Result<RoleRow> {
        sqlx::query_as::<_, RoleRow>(
            "INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id, name, description",
        )
        .bind(name)
        .bind(description)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn update_role(&self, name: &str, description: &str) -> sqlx::Result<Option<RoleRow>> {
        sqlx::query_as::<_, RoleRow>(
            "UPDATE roles SET description = $2 WHERE name = $1 RETURNING id, name, description",
        )
        .bind(name)
        .bind(description)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn delete_role(&self, name: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM roles WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_roles(&self) -> sqlx::Result<Vec<RoleRow>> {
        sqlx::query_as::<_, RoleRow>("SELECT id, name, description FROM roles ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn list_role_permissions(&self, role_id: i64) -> sqlx::Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id \
             WHERE rp.role_id = $1 ORDER BY p.name",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn list_permissions(&self) -> sqlx::Result<Vec<RoleRow>> {
        // reuse RoleRow shape (id, name, description) for permissions
        sqlx::query_as::<_, RoleRow>("SELECT id, name, description FROM permissions ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn grant_permission(&self, role_name: &str, perm_name: &str) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id) \
             SELECT r.id, p.id FROM roles r, permissions p \
             WHERE r.name = $1 AND p.name = $2 ON CONFLICT DO NOTHING",
        )
        .bind(role_name)
        .bind(perm_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_permission(&self, role_name: &str, perm_name: &str) -> sqlx::Result<()> {
        sqlx::query(
            "DELETE FROM role_permissions \
             WHERE role_id = (SELECT id FROM roles WHERE name = $1) \
               AND permission_id = (SELECT id FROM permissions WHERE name = $2)",
        )
        .bind(role_name)
        .bind(perm_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
