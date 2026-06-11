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
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
pub struct ApiKeyMeta {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
pub struct RoleWithPermsRow {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
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
            "SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until, totp_secret, totp_enabled, deleted_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> sqlx::Result<Option<UserRow>> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until, totp_secret, totp_enabled, deleted_at FROM users WHERE id = $1",
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

    /// True if the identity exists and is not soft-deleted.
    pub async fn is_user_active(&self, id: Uuid) -> sqlx::Result<bool> {
        let v: Option<bool> = sqlx::query_scalar("SELECT (deleted_at IS NULL) FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(v.unwrap_or(false))
    }

    /// Soft-delete (or hard-delete when `hard`) the identity and enqueue a
    /// UserDeleted event in one transaction. Soft also revokes refresh tokens.
    /// Plain soft-delete (no event) — used by the saga compensator.
    pub async fn soft_delete_user(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_user_event_soft(
        &self,
        id: Uuid,
        hard: bool,
        event_type: &str,
        payload: &str,
    ) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        if hard {
            sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL")
                .bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
                .bind(id).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO outbox (aggregate_id, event_type, payload) VALUES ($1, $2, $3::jsonb)")
            .bind(id).bind(event_type).bind(payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Restore a soft-deleted identity and enqueue a UserRestored event.
    pub async fn restore_user_event(&self, id: Uuid, event_type: &str, payload: &str) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET deleted_at = NULL, updated_at = now() WHERE id = $1")
            .bind(id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO outbox (aggregate_id, event_type, payload) VALUES ($1, $2, $3::jsonb)")
            .bind(id).bind(event_type).bind(payload).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    // ── 2FA / TOTP (v0.9) ──

    pub async fn set_totp_secret(&self, id: Uuid, secret: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET totp_secret = $2, totp_enabled = false, updated_at = now() WHERE id = $1")
            .bind(id).bind(secret).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn enable_totp(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET totp_enabled = true, updated_at = now() WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn disable_totp(&self, id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE users SET totp_secret = NULL, totp_enabled = false, updated_at = now() WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn insert_recovery_code(&self, user_id: Uuid, code_hash: &str) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
            .bind(user_id).bind(code_hash).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete_recovery_codes(&self, user_id: Uuid) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
            .bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Atomically spend a one-time recovery code; true on success.
    pub async fn consume_recovery_code(&self, user_id: Uuid, code_hash: &str) -> sqlx::Result<bool> {
        let id: Option<i64> = sqlx::query_scalar(
            "UPDATE totp_recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING id",
        )
        .bind(user_id).bind(code_hash).fetch_optional(&self.pool).await?;
        Ok(id.is_some())
    }

    // ── API keys (v0.9) ──

    pub async fn create_api_key(&self, id: &str, user_id: Uuid, key_hash: &str, name: &str, scopes: &[String], expires_at: Option<DateTime<Utc>>) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO api_keys (id, user_id, key_hash, name, scopes, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(id).bind(user_id).bind(key_hash).bind(name).bind(scopes).bind(expires_at)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_api_key_by_hash(&self, key_hash: &str) -> sqlx::Result<Option<ApiKeyRow>> {
        sqlx::query_as::<_, ApiKeyRow>("SELECT id, user_id, scopes, expires_at, revoked_at FROM api_keys WHERE key_hash = $1")
            .bind(key_hash).fetch_optional(&self.pool).await
    }

    pub async fn list_api_keys(&self, user_id: Uuid) -> sqlx::Result<Vec<ApiKeyMeta>> {
        sqlx::query_as::<_, ApiKeyMeta>("SELECT id, name, scopes, expires_at, last_used_at, created_at FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC")
            .bind(user_id).fetch_all(&self.pool).await
    }

    pub async fn revoke_api_key(&self, id: &str, user_id: Uuid) -> sqlx::Result<()> {
        sqlx::query("UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL")
            .bind(id).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn touch_api_key(&self, id: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE id = $1")
            .bind(id).execute(&self.pool).await?;
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

    /// Roles + their permission names in one query (avoids the N+1 over roles).
    pub async fn list_roles_with_permissions(&self) -> sqlx::Result<Vec<RoleWithPermsRow>> {
        sqlx::query_as::<_, RoleWithPermsRow>(
            "SELECT r.id, r.name, r.description, \
                    COALESCE(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), '{}')::text[] AS permissions \
             FROM roles r \
             LEFT JOIN role_permissions rp ON rp.role_id = r.id \
             LEFT JOIN permissions p ON p.id = rp.permission_id \
             GROUP BY r.id, r.name, r.description \
             ORDER BY r.name",
        )
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

// ── Integration tests against a real Postgres (testcontainers) ──
// Run with: cargo test --features integration   (needs Docker)
#[cfg(all(test, feature = "integration"))]
mod integration {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::testcontainers::ContainerAsync;

    // Spin up a throwaway Postgres, apply the embedded migrations, return a Repo.
    // The container is dropped (stopped) when the returned guard is dropped.
    async fn setup() -> (Repo, ContainerAsync<Postgres>) {
        let node = Postgres::default().start().await.expect("start postgres");
        let port = node.get_host_port_ipv4(5432).await.expect("port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("connect");
        sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");
        (Repo::new(pool), node)
    }

    #[tokio::test]
    async fn user_lifecycle_soft_delete_restore() {
        let (repo, _node) = setup().await;
        let id = repo.create_user("alice@test.local", "argon2$x").await.unwrap();
        let got = repo.get_user_by_email("alice@test.local").await.unwrap().unwrap();
        assert_eq!(got.id, id);
        assert!(repo.is_user_active(id).await.unwrap());

        repo.delete_user_event_soft(id, false, "user.deleted", "{}").await.unwrap();
        assert!(!repo.is_user_active(id).await.unwrap(), "soft-deleted should be inactive");

        repo.restore_user_event(id, "user.restored", "{}").await.unwrap();
        assert!(repo.is_user_active(id).await.unwrap(), "restored should be active");
    }

    #[tokio::test]
    async fn list_roles_with_permissions_single_query() {
        let (repo, _node) = setup().await;
        let roles = repo.list_roles_with_permissions().await.unwrap();
        let admin = roles.iter().find(|r| r.name == "admin").expect("admin role seeded");
        assert!(!admin.permissions.is_empty(), "admin should carry perms via the single query");
    }

    #[tokio::test]
    async fn api_key_create_get_revoke() {
        let (repo, _node) = setup().await;
        let id = repo.create_user("key@test.local", "x").await.unwrap();
        repo.create_api_key("k1", id, "hash1", "ci", &["user:read".to_string()], None)
            .await
            .unwrap();
        let row = repo.get_api_key_by_hash("hash1").await.unwrap().unwrap();
        assert_eq!(row.user_id, id);
        assert_eq!(row.scopes, vec!["user:read".to_string()]);
        repo.revoke_api_key("k1", id).await.unwrap();
        let row2 = repo.get_api_key_by_hash("hash1").await.unwrap().unwrap();
        assert!(row2.revoked_at.is_some(), "key should be revoked");
    }

    #[tokio::test]
    async fn recovery_code_single_use() {
        let (repo, _node) = setup().await;
        let id = repo.create_user("rec@test.local", "x").await.unwrap();
        repo.insert_recovery_code(id, "rc-hash").await.unwrap();
        assert!(repo.consume_recovery_code(id, "rc-hash").await.unwrap());
        assert!(
            !repo.consume_recovery_code(id, "rc-hash").await.unwrap(),
            "a recovery code must be one-time"
        );
    }
}
