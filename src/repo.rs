//! Postgres access for the auth service via sqlx (runtime-checked queries).

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres};
use uuid::Uuid;

/// The fixed default-tenant UUID seeded by migration 0010 (mirrors
/// grpc::DEFAULT_TENANT_ID). Used to set app.tenant_id for the default-tenant
/// user_roles writes in register/bootstrap so they pass RLS once the app
/// connects as the non-superuser iam_app (Phase 3c).
const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

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
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
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
    pub replaced_by: Option<String>,
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
}

/// A tenant the user is an active member of (M6).
#[derive(FromRow)]
pub struct MembershipRow {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub tenant_name: String,
    pub status: String,
}

/// A tenant row (M6.4 administration).
#[derive(FromRow)]
pub struct TenantRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub status: String,
}

/// A project row (M6.4 administration).
#[derive(FromRow)]
pub struct ProjectRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub name: String,
}

/// A tenant member (M6.4 administration).
#[derive(FromRow)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub status: String,
}

/// A user's role assignment within a tenant (M6) — project_* NULL = tenant-wide.
#[derive(FromRow)]
pub struct RoleAssignmentRow {
    pub role: String,
    pub project_id: Option<Uuid>,
    pub project_slug: Option<String>,
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
        // The user_roles write below targets the default tenant (column DEFAULT) — set
        // app.tenant_id so it passes RLS WITH CHECK once connected as iam_app (Phase 3c).
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(DEFAULT_TENANT_ID)
            .execute(&mut *tx)
            .await?;
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

    pub async fn create_api_key(&self, id: &str, user_id: Uuid, key_hash: &str, name: &str, scopes: &[String], expires_at: Option<DateTime<Utc>>, tenant_id: Uuid, project_id: Option<Uuid>) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO api_keys (id, user_id, key_hash, name, scopes, expires_at, tenant_id, project_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(id).bind(user_id).bind(key_hash).bind(name).bind(scopes).bind(expires_at).bind(tenant_id).bind(project_id)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_api_key_by_hash(&self, key_hash: &str) -> sqlx::Result<Option<ApiKeyRow>> {
        sqlx::query_as::<_, ApiKeyRow>("SELECT id, user_id, scopes, expires_at, revoked_at, tenant_id, project_id FROM api_keys WHERE key_hash = $1")
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
        // The user_roles write below targets the default tenant (column DEFAULT) — set
        // app.tenant_id so it passes RLS WITH CHECK once connected as iam_app (Phase 3c).
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(DEFAULT_TENANT_ID)
            .execute(&mut *tx)
            .await?;
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

    pub async fn insert_audit(&self, actor_id: &str, actor_email: &str, action: &str, target: &str, detail: &str, tenant_id: Option<Uuid>) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO audit_events (actor_id, actor_email, action, target, detail, tenant_id) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(actor_id).bind(actor_email).bind(action).bind(target).bind(detail).bind(tenant_id)
            .execute(&self.pool).await?;
        Ok(())
    }

    /// List the audit trail of a single tenant. Pre-tenant rows (login/register)
    /// carry a NULL tenant_id and are excluded from every tenant view by design.
    pub async fn list_audit(&self, tenant_id: Uuid, limit: i64) -> sqlx::Result<Vec<AuditRow>> {
        sqlx::query_as::<_, AuditRow>(
            "SELECT id, actor_id, actor_email, action, target, detail, created_at \
             FROM audit_events WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(tenant_id)
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
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, tenant_id, project_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(tenant_id)
        .bind(project_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_refresh_token(&self, token_hash: &str) -> sqlx::Result<Option<RefreshTokenRow>> {
        sqlx::query_as::<_, RefreshTokenRow>(
            "SELECT user_id, expires_at, revoked_at, replaced_by, tenant_id, project_id \
             FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    /// M6: tenants the user is an active member of (joined to the tenant row).
    pub async fn list_memberships(&self, user_id: Uuid) -> sqlx::Result<Vec<MembershipRow>> {
        sqlx::query_as::<_, MembershipRow>(
            "SELECT t.id AS tenant_id, t.slug AS tenant_slug, t.name AS tenant_name, m.status \
             FROM memberships m JOIN tenants t ON t.id = m.tenant_id \
             WHERE m.user_id = $1 AND m.status = 'active' AND t.status = 'active' \
             ORDER BY t.name",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    /// M6: whether the user is an active member of an active tenant. Both the
    /// membership and the tenant must be active, so suspending a tenant
    /// immediately invalidates every member's tokens on their next request.
    pub async fn is_active_member(&self, user_id: Uuid, tenant_id: Uuid) -> sqlx::Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memberships m \
             JOIN tenants t ON t.id = m.tenant_id \
             WHERE m.user_id = $1 AND m.tenant_id = $2 \
               AND m.status = 'active' AND t.status = 'active')",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
    }

    /// M6: the default project of a tenant (lowest-sorted), if any.
    pub async fn get_default_project(&self, tenant_id: Uuid) -> sqlx::Result<Option<Uuid>> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM projects WHERE tenant_id = $1 ORDER BY slug LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
    }

    /// M6: enroll a user as an active member of a tenant (idempotent).
    pub async fn create_membership(&self, user_id: Uuid, tenant_id: Uuid) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO memberships (user_id, tenant_id, status) VALUES ($1, $2, 'active') \
             ON CONFLICT (user_id, tenant_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// M6.4: create a tenant and, in the same transaction, enroll the creator as
    /// its first member and grant them the admin role scoped to it (their
    /// platform role does not carry over — RBAC is per tenant).
    pub async fn create_tenant_with_admin(
        &self,
        slug: &str,
        name: &str,
        creator: Uuid,
    ) -> sqlx::Result<TenantRow> {
        let mut tx = self.pool.begin().await?;
        let t = sqlx::query_as::<_, TenantRow>(
            "INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING id, slug, name, status",
        )
        .bind(slug)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO memberships (user_id, tenant_id, status) VALUES ($1, $2, 'active') \
             ON CONFLICT (user_id, tenant_id) DO NOTHING",
        )
        .bind(creator)
        .bind(t.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id, tenant_id) \
             SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'admin' AND r.tenant_id IS NULL \
             ON CONFLICT DO NOTHING",
        )
        .bind(creator)
        .bind(t.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(t)
    }

    /// M6.4: every tenant (platform view).
    pub async fn list_tenants(&self) -> sqlx::Result<Vec<TenantRow>> {
        sqlx::query_as::<_, TenantRow>("SELECT id, slug, name, status FROM tenants ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    /// M6.4: create a project in a tenant. Phase 3b: runs under RLS so WITH CHECK
    /// pins the new row to the active tenant at the database.
    pub async fn create_project(&self, tenant_id: Uuid, slug: &str, name: &str) -> sqlx::Result<ProjectRow> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRow>(
            "INSERT INTO projects (tenant_id, slug, name) VALUES ($1, $2, $3) \
             RETURNING id, tenant_id, slug, name",
        )
        .bind(tenant_id)
        .bind(slug)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// M6.4: enroll a member into a tenant via the admin path, under RLS (WITH
    /// CHECK pins the row to the active tenant). Distinct from `create_membership`,
    /// which the pre-auth register/bootstrap paths use on the direct connection.
    pub async fn add_member(&self, user_id: Uuid, tenant_id: Uuid) -> sqlx::Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "INSERT INTO memberships (user_id, tenant_id, status) VALUES ($1, $2, 'active') \
             ON CONFLICT (user_id, tenant_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// M6.4b: begin a transaction that assumes the restricted iam_rls role with
    /// app.tenant_id set, so Postgres RLS enforces tenant isolation on every query
    /// run inside it — on reads (a forgotten WHERE still can't leak another
    /// tenant) and, for Phase 3b, on writes (WITH CHECK rejects a cross-tenant
    /// INSERT/UPDATE). The policy is fail-closed when app.tenant_id is unset.
    async fn tenant_tx(&self, tenant_id: Uuid) -> sqlx::Result<sqlx::Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE iam_rls").execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Phase 3c: like tenant_tx but ONLY sets app.tenant_id — it does NOT elevate to
    /// iam_rls. For the pre-tenant / hot auth paths that read or write a Kept-strict
    /// RLS table (roles/user_roles) with a known tenant. While the app still connects
    /// as the superuser `app`, setting the GUC is a no-op (superuser bypasses RLS), so
    /// behaviour is unchanged; once the connection role is the non-superuser iam_app,
    /// the GUC is what satisfies the fail-closed policy. Not elevating to iam_rls keeps
    /// it a no-op pre-cutover instead of enforcing RLS early on these hot paths.
    async fn tenant_guc_tx(&self, tenant_id: &str) -> sqlx::Result<sqlx::Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// M6.4b: projects in a tenant, read under Row-Level Security.
    pub async fn list_projects_by_tenant(&self, tenant_id: Uuid) -> sqlx::Result<Vec<ProjectRow>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query_as::<_, ProjectRow>(
            "SELECT id, tenant_id, slug, name FROM projects WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// M6.4b: members of a tenant (joined to users), read under Row-Level Security.
    pub async fn list_members_by_tenant(&self, tenant_id: Uuid) -> sqlx::Result<Vec<MemberRow>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let rows = sqlx::query_as::<_, MemberRow>(
            "SELECT u.id AS user_id, u.email, m.status FROM memberships m \
             JOIN users u ON u.id = m.user_id WHERE m.tenant_id = $1 ORDER BY u.email",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// M6.4: remove a user from a tenant. Phase 3b: runs under RLS so the DELETE
    /// only sees (and can only remove) the active tenant's membership row.
    pub async fn remove_member(&self, user_id: Uuid, tenant_id: Uuid) -> sqlx::Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query("DELETE FROM memberships WHERE user_id = $1 AND tenant_id = $2")
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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

    /// Mark a token rotated (revoked) and record its successor, so a concurrent
    /// re-presentation within the grace window is told apart from a logout-revoked
    /// token (which leaves replaced_by NULL).
    pub async fn rotate_refresh_token(&self, token_hash: &str, replaced_by: &str) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2 \
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .bind(replaced_by)
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

    /// M6.3: roles scoped to the token's tenant (and optional project).
    /// Tenant-wide assignments (project_id IS NULL) always apply; project-scoped
    /// ones apply only when the token names that project. A NULL project_id
    /// (tenant-wide token) therefore yields only tenant-wide roles.
    pub async fn get_user_roles_scoped(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> sqlx::Result<Vec<String>> {
        // user_roles + roles are Kept-strict RLS (Phase 3c) — read with app.tenant_id
        // set so a non-superuser iam_app connection sees this tenant's rows.
        let mut tx = self.tenant_guc_tx(&tenant_id.to_string()).await?;
        let rows = sqlx::query_scalar(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id \
             WHERE ur.user_id = $1 AND ur.tenant_id = $2 \
               AND (ur.project_id IS NULL OR ur.project_id = $3) ORDER BY r.name",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    /// M6.3: permissions scoped to the token's tenant (and optional project).
    pub async fn get_user_permissions_scoped(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> sqlx::Result<Vec<String>> {
        // Joins user_roles + roles (Kept-strict) — read under app.tenant_id so an
        // iam_app connection can see the rows.
        let mut tx = self.tenant_guc_tx(&tenant_id.to_string()).await?;
        let rows = sqlx::query_scalar(
            "SELECT DISTINCT p.name FROM user_roles ur \
             JOIN role_permissions rp ON rp.role_id = ur.role_id \
             JOIN permissions p ON p.id = rp.permission_id \
             WHERE ur.user_id = $1 AND ur.tenant_id = $2 \
               AND (ur.project_id IS NULL OR ur.project_id = $3) ORDER BY p.name",
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    pub async fn role_exists(&self, name: &str) -> sqlx::Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)")
                .bind(name)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    /// M6: a role visible in a tenant — its own role or a built-in template.
    pub async fn role_in_tenant(&self, name: &str, tenant_id: Uuid) -> sqlx::Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1 AND (tenant_id = $2 OR tenant_id IS NULL))",
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
    }

    /// M6: a role OWNED by the tenant (not a shared built-in template).
    pub async fn tenant_role_exists(&self, name: &str, tenant_id: Uuid) -> sqlx::Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1 AND tenant_id = $2)",
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
    }

    /// M6: whether a project belongs to a tenant.
    pub async fn is_project_in_tenant(&self, project_id: Uuid, tenant_id: Uuid) -> sqlx::Result<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(project_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn assign_role(
        &self,
        user_id: Uuid,
        role_name: &str,
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> sqlx::Result<()> {
        // Resolve the role within the tenant (own role, else a built-in template,
        // preferring the tenant-specific one) — never another tenant's role.
        // Phase 3b: under RLS, the role lookup only sees this tenant's roles +
        // NULL templates, and WITH CHECK pins the new user_roles row to the tenant.
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id, tenant_id, project_id) \
             SELECT $1, r.id, $3, $4 FROM roles r \
             WHERE r.name = $2 AND (r.tenant_id = $3 OR r.tenant_id IS NULL) \
             ORDER BY r.tenant_id NULLS LAST LIMIT 1 ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_name)
        .bind(tenant_id)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_role(
        &self,
        user_id: Uuid,
        role_name: &str,
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> sqlx::Result<()> {
        // Phase 3b: under RLS the DELETE only sees this tenant's assignments.
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "DELETE FROM user_roles ur \
             WHERE ur.user_id = $1 AND ur.role_id = (SELECT r.id FROM roles r WHERE r.name = $2) \
               AND ur.tenant_id = $3 AND ur.project_id IS NOT DISTINCT FROM $4",
        )
        .bind(user_id)
        .bind(role_name)
        .bind(tenant_id)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// M6: a user's role assignments in a tenant, each with its project scope.
    pub async fn get_user_role_assignments(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> sqlx::Result<Vec<RoleAssignmentRow>> {
        sqlx::query_as::<_, RoleAssignmentRow>(
            "SELECT r.name AS role, ur.project_id, p.slug AS project_slug \
             FROM user_roles ur JOIN roles r ON r.id = ur.role_id \
             LEFT JOIN projects p ON p.id = ur.project_id \
             WHERE ur.user_id = $1 AND ur.tenant_id = $2 \
             ORDER BY r.name, p.slug NULLS FIRST",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn create_role(&self, name: &str, description: &str, tenant_id: Uuid) -> sqlx::Result<RoleRow> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query_as::<_, RoleRow>(
            "INSERT INTO roles (name, description, tenant_id) VALUES ($1, $2, $3) RETURNING id, name, description",
        )
        .bind(name)
        .bind(description)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    pub async fn update_role(&self, name: &str, description: &str, tenant_id: Uuid) -> sqlx::Result<Option<RoleRow>> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let row = sqlx::query_as::<_, RoleRow>(
            "UPDATE roles SET description = $2 WHERE name = $1 AND tenant_id = $3 RETURNING id, name, description",
        )
        .bind(name)
        .bind(description)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    pub async fn delete_role(&self, name: &str, tenant_id: Uuid) -> sqlx::Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query("DELETE FROM roles WHERE name = $1 AND tenant_id = $2")
            .bind(name)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_roles(&self) -> sqlx::Result<Vec<RoleRow>> {
        sqlx::query_as::<_, RoleRow>("SELECT id, name, description FROM roles ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    /// M6: the tenant's own roles + the shared built-in templates, each with its
    /// permissions in one query (avoids the N+1 over roles).
    pub async fn list_roles_with_permissions(&self, tenant_id: Uuid) -> sqlx::Result<Vec<RoleWithPermsRow>> {
        sqlx::query_as::<_, RoleWithPermsRow>(
            "SELECT r.id, r.name, r.description, \
                    COALESCE(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), '{}')::text[] AS permissions \
             FROM roles r \
             LEFT JOIN role_permissions rp ON rp.role_id = r.id \
             LEFT JOIN permissions p ON p.id = rp.permission_id \
             WHERE r.tenant_id = $1 OR r.tenant_id IS NULL \
             GROUP BY r.id, r.name, r.description \
             ORDER BY r.name",
        )
        .bind(tenant_id)
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

    /// M6: grant a permission to one of the TENANT's own roles (built-in
    /// templates are platform-managed and shared, so not mutable per-tenant).
    pub async fn grant_permission(&self, role_name: &str, perm_name: &str, tenant_id: Uuid) -> sqlx::Result<()> {
        // Phase 3b: under RLS the role lookup only resolves this tenant's roles.
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id) \
             SELECT r.id, p.id FROM roles r, permissions p \
             WHERE r.name = $1 AND r.tenant_id = $3 AND p.name = $2 ON CONFLICT DO NOTHING",
        )
        .bind(role_name)
        .bind(perm_name)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_permission(&self, role_name: &str, perm_name: &str, tenant_id: Uuid) -> sqlx::Result<()> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        sqlx::query(
            "DELETE FROM role_permissions \
             WHERE role_id = (SELECT id FROM roles WHERE name = $1 AND tenant_id = $3) \
               AND permission_id = (SELECT id FROM permissions WHERE name = $2)",
        )
        .bind(role_name)
        .bind(perm_name)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
        // admin is a built-in template (tenant_id NULL), visible from any tenant.
        let roles = repo.list_roles_with_permissions(Uuid::nil()).await.unwrap();
        let admin = roles.iter().find(|r| r.name == "admin").expect("admin role seeded");
        assert!(!admin.permissions.is_empty(), "admin should carry perms via the single query");
    }

    #[tokio::test]
    async fn api_key_create_get_revoke() {
        let (repo, _node) = setup().await;
        let id = repo.create_user("key@test.local", "x").await.unwrap();
        // tenant_id is a NOT-NULL FK to the seeded default tenant (M6 backfill).
        let default_tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        repo.create_api_key("k1", id, "hash1", "ci", &["user:read".to_string()], None, default_tenant, None)
            .await
            .unwrap();
        let row = repo.get_api_key_by_hash("hash1").await.unwrap().unwrap();
        assert_eq!(row.user_id, id);
        assert_eq!(row.scopes, vec!["user:read".to_string()]);
        repo.revoke_api_key("k1", id).await.unwrap();
        let row2 = repo.get_api_key_by_hash("hash1").await.unwrap().unwrap();
        assert!(row2.revoked_at.is_some(), "key should be revoked");
    }

    // Phase 3b: a tenant-scoped write run via the iam_rls path (create_project
    // here) must succeed for the active tenant, and a write targeting ANOTHER
    // tenant while scoped to A must be rejected by the RLS WITH CHECK policy.
    #[tokio::test]
    async fn rls_with_check_rejects_cross_tenant_write() {
        let (repo, _node) = setup().await;
        let tenant_a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(); // seeded default
        let tenant_b: Uuid =
            sqlx::query_scalar("INSERT INTO tenants (slug, name) VALUES ('beta', 'Beta') RETURNING id")
                .fetch_one(&repo.pool)
                .await
                .unwrap();

        // The wrapped write path commits for the active tenant.
        repo.create_project(tenant_a, "ok", "OK").await.unwrap();

        // Scoped to A, an INSERT for B is rejected by WITH CHECK.
        let mut tx = repo.pool.begin().await.unwrap();
        sqlx::query("SET LOCAL ROLE iam_rls").execute(&mut *tx).await.unwrap();
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant_a.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let res = sqlx::query("INSERT INTO projects (tenant_id, slug, name) VALUES ($1, 'evil', 'Evil')")
            .bind(tenant_b)
            .execute(&mut *tx)
            .await;
        assert!(res.is_err(), "cross-tenant write must be rejected by RLS WITH CHECK");
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
