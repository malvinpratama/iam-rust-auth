//! Tonic implementation of AuthService.

use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use common::email::Sender;
use common::jwt::JwtManager;
use common::password;
use proto::auth::v1::auth_service_server::AuthService;
use proto::auth::v1::*;

use crate::repo::Repo;

const DEFAULT_ROLE: &str = "user";

pub struct AuthSvc {
    repo: Repo,
    jwt: JwtManager,
    refresh_ttl_secs: i64,
    dummy_hash: String, // constant-time login on unknown users
    mail: Box<dyn Sender>,
}

/// Enforce a permission from the gateway-supplied identity metadata
/// (defense-in-depth: the service re-checks, not just the gateway).
fn require_perm(md: &MetadataMap, perm: &str) -> Result<(), Status> {
    let ok = md
        .get("x-user-permissions")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|p| p == perm))
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Status::permission_denied(format!("permission denied: {perm}")))
    }
}

fn meta(md: &MetadataMap, key: &str) -> String {
    md.get(key).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

impl AuthSvc {
    pub fn new(repo: Repo, jwt: JwtManager, refresh_ttl_secs: i64, mail: Box<dyn Sender>) -> Self {
        let dummy_hash = password::hash("constant-time-dummy-password").unwrap_or_default();
        Self { repo, jwt, refresh_ttl_secs, dummy_hash, mail }
    }

    /// Record a sensitive action with an explicit actor.
    async fn audit_as(&self, actor_id: &str, actor_email: &str, action: &str, target: &str, detail: &str) {
        if common::config::audit_enabled() {
            let _ = self.repo.insert_audit(actor_id, actor_email, action, target, detail).await;
        }
    }

    /// Record a sensitive action with the actor taken from gateway metadata.
    async fn audit(&self, md: &MetadataMap, action: &str, target: &str, detail: &str) {
        let actor_id = meta(md, "x-user-id");
        let actor_email = meta(md, "x-user-email");
        self.audit_as(&actor_id, &actor_email, action, target, detail).await;
    }

    async fn issue_tokens(&self, user_id: Uuid, email: &str) -> Result<TokenPair, Status> {
        let access = self
            .jwt
            .issue(&user_id.to_string(), email)
            .map_err(|_| Status::internal("failed to sign token"))?;
        let refresh = gen_refresh_token();
        let expires = Utc::now() + Duration::seconds(self.refresh_ttl_secs);
        self.repo
            .create_refresh_token(user_id, &hash_token(&refresh), expires)
            .await
            .map_err(|_| Status::internal("failed to persist refresh token"))?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            expires_in: self.jwt.access_ttl_secs(),
            token_type: "Bearer".into(),
        })
    }
}

#[tonic::async_trait]
impl AuthService for AuthSvc {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        if req.email.is_empty() || req.password.is_empty() {
            return Err(Status::invalid_argument("email and password are required"));
        }
        let hash =
            password::hash(&req.password).map_err(|_| Status::internal("failed to hash password"))?;
        // Create the identity and enqueue a UserRegistered event in one tx
        // (outbox pattern). The user service creates the profile asynchronously.
        let id = Uuid::new_v4();
        let display = req.email.split('@').next().unwrap_or(&req.email).to_string();
        let payload = serde_json::to_string(&common::events::UserRegistered {
            user_id: id.to_string(),
            email: req.email.clone(),
            display_name: display,
        })
        .map_err(|_| Status::internal("failed to encode event"))?;
        self.repo
            .create_user_with_role_event(
                id,
                &req.email,
                &hash,
                DEFAULT_ROLE,
                common::events::TYPE_USER_REGISTERED,
                &payload,
            )
            .await
            .map_err(|_| Status::already_exists("email already registered"))?;
        self.audit_as(&id.to_string(), &req.email, "user.register", "", "").await;
        Ok(Response::new(RegisterResponse {
            user_id: id.to_string(),
            email: req.email,
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        let req = request.into_inner();
        let user = match self
            .repo
            .get_user_by_email(&req.email)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            Some(u) => u,
            None => {
                // Unknown user: still run a verify so timing doesn't leak existence.
                let _ = password::verify(&self.dummy_hash, &req.password);
                return Err(Status::unauthenticated("invalid credentials"));
            }
        };

        // Account lockout: refuse while locked.
        if let Some(until) = user.locked_until {
            if until > Utc::now() {
                return Err(Status::unauthenticated("account temporarily locked, try again later"));
            }
        }

        if !password::verify(&user.password_hash, &req.password) {
            let max = common::config::login_max_failures();
            if max > 0 {
                if let Ok(n) = self.repo.increment_login_failure(user.id).await {
                    if (n as i64) >= max {
                        let until = Utc::now() + Duration::seconds(common::config::login_lockout_secs());
                        let _ = self.repo.lock_user(user.id, until).await;
                        self.audit_as(&user.id.to_string(), &user.email, "login.locked", "", "too many failed attempts").await;
                    }
                }
            }
            self.audit_as(&user.id.to_string(), &user.email, "login.failure", "", "").await;
            return Err(Status::unauthenticated("invalid credentials"));
        }

        if common::config::require_email_verification() && !user.email_verified {
            return Err(Status::unauthenticated("email not verified"));
        }

        let _ = self.repo.reset_login_state(user.id).await;
        self.audit_as(&user.id.to_string(), &user.email, "login.success", "", "").await;
        let pair = self.issue_tokens(user.id, &user.email).await?;
        Ok(Response::new(pair))
    }

    async fn refresh(
        &self,
        request: Request<RefreshRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        let req = request.into_inner();
        let hash = hash_token(&req.refresh_token);
        let row = self
            .repo
            .get_refresh_token(&hash)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::unauthenticated("invalid refresh token"))?;
        if row.revoked_at.is_some() {
            // Reuse of an already-revoked token suggests theft → revoke the family.
            let _ = self.repo.revoke_all_user_refresh_tokens(row.user_id).await;
            self.audit_as(&row.user_id.to_string(), "", "refresh.reuse_detected", "", "all sessions revoked").await;
            return Err(Status::unauthenticated("refresh token revoked"));
        }
        if row.expires_at < Utc::now() {
            return Err(Status::unauthenticated("refresh token expired"));
        }
        let user = self
            .repo
            .get_user_by_id(row.user_id)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::unauthenticated("user not found"))?;
        // Rotate: revoke the presented token, issue a fresh pair.
        self.repo
            .revoke_refresh_token(&hash)
            .await
            .map_err(|_| Status::internal("failed to rotate token"))?;
        let pair = self.issue_tokens(user.id, &user.email).await?;
        Ok(Response::new(pair))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        self.repo
            .revoke_refresh_token(&hash_token(&req.refresh_token))
            .await
            .map_err(|_| Status::internal("failed to revoke token"))?;
        // Best-effort: denylist the access token (by jti) so it stops working now.
        if !req.access_token.is_empty() {
            if let Ok(claims) = self.jwt.parse(&req.access_token) {
                if let Some(exp) = chrono::DateTime::from_timestamp(claims.exp, 0) {
                    let _ = self.repo.revoke_access_jti(&claims.jti, exp).await;
                }
            }
        }
        self.audit(&md, "auth.logout", "", "").await;
        Ok(Response::new(LogoutResponse { success: true }))
    }

    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();
        let claims = self
            .jwt
            .parse(&req.access_token)
            .map_err(|_| Status::unauthenticated("invalid or expired token"))?;
        if self
            .repo
            .is_token_revoked(&claims.jti)
            .await
            .map_err(|_| Status::internal("failed to check token status"))?
        {
            return Err(Status::unauthenticated("token revoked"));
        }
        let user_id =
            Uuid::parse_str(&claims.sub).map_err(|_| Status::unauthenticated("invalid subject"))?;
        let roles = self
            .repo
            .get_user_roles(user_id)
            .await
            .map_err(|_| Status::internal("failed to load roles"))?;
        let permissions = self
            .repo
            .get_user_permissions(user_id)
            .await
            .map_err(|_| Status::internal("failed to load permissions"))?;
        Ok(Response::new(ValidateTokenResponse {
            user_id: claims.sub,
            email: claims.email,
            roles,
            permissions,
        }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        require_perm(request.metadata(), "user:delete")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        let payload = serde_json::to_string(&common::events::UserDeleted {
            user_id: req.user_id.clone(),
        })
        .map_err(|_| Status::internal("failed to encode event"))?;
        self.repo
            .delete_user_event(user_id, common::events::TYPE_USER_DELETED, &payload)
            .await
            .map_err(|_| Status::internal("failed to delete user"))?;
        self.audit(&md, "user.delete", &req.user_id, "").await;
        Ok(Response::new(DeleteUserResponse { success: true }))
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<Role>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let role = self
            .repo
            .create_role(&req.name, &req.description)
            .await
            .map_err(|_| Status::already_exists("role already exists"))?;
        self.audit(&md, "role.create", &req.name, "").await;
        Ok(Response::new(Role {
            id: role.id,
            name: role.name,
            description: role.description,
            permissions: vec![],
        }))
    }

    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<Role>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let req = request.into_inner();
        let role = self
            .repo
            .update_role(&req.name, &req.description)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("role not found"))?;
        Ok(Response::new(Role {
            id: role.id,
            name: role.name,
            description: role.description,
            permissions: vec![],
        }))
    }

    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        if req.name == "admin" || req.name == "user" {
            return Err(Status::failed_precondition("cannot delete built-in role"));
        }
        if !self
            .repo
            .role_exists(&req.name)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found"));
        }
        self.repo
            .delete_role(&req.name)
            .await
            .map_err(|_| Status::internal("failed to delete role"))?;
        self.audit(&md, "role.delete", &req.name, "").await;
        Ok(Response::new(DeleteRoleResponse { success: true }))
    }

    async fn list_roles(
        &self,
        _request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let rows = self
            .repo
            .list_roles()
            .await
            .map_err(|_| Status::internal("failed to list roles"))?;
        let mut roles = Vec::with_capacity(rows.len());
        for r in rows {
            let perms = self
                .repo
                .list_role_permissions(r.id)
                .await
                .map_err(|_| Status::internal("failed to list role permissions"))?;
            roles.push(Role {
                id: r.id,
                name: r.name,
                description: r.description,
                permissions: perms,
            });
        }
        Ok(Response::new(ListRolesResponse { roles }))
    }

    async fn assign_role(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        require_perm(request.metadata(), "role:assign")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        if !self
            .repo
            .role_exists(&req.role_name)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found"));
        }
        self.repo
            .assign_role(user_id, &req.role_name)
            .await
            .map_err(|_| Status::internal("failed to assign role"))?;
        self.audit(&md, "role.assign", &req.user_id, &req.role_name).await;
        Ok(Response::new(AssignRoleResponse { success: true }))
    }

    async fn revoke_role(
        &self,
        request: Request<RevokeRoleRequest>,
    ) -> Result<Response<RevokeRoleResponse>, Status> {
        require_perm(request.metadata(), "role:assign")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        if !self
            .repo
            .role_exists(&req.role_name)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found"));
        }
        self.repo
            .revoke_role(user_id, &req.role_name)
            .await
            .map_err(|_| Status::internal("failed to revoke role"))?;
        self.audit(&md, "role.revoke", &req.user_id, &req.role_name).await;
        Ok(Response::new(RevokeRoleResponse { success: true }))
    }

    async fn list_permissions(
        &self,
        _request: Request<ListPermissionsRequest>,
    ) -> Result<Response<ListPermissionsResponse>, Status> {
        let rows = self
            .repo
            .list_permissions()
            .await
            .map_err(|_| Status::internal("failed to list permissions"))?;
        let permissions = rows
            .into_iter()
            .map(|p| Permission {
                id: p.id,
                name: p.name,
                description: p.description,
            })
            .collect();
        Ok(Response::new(ListPermissionsResponse { permissions }))
    }

    async fn grant_permission(
        &self,
        request: Request<GrantPermissionRequest>,
    ) -> Result<Response<GrantPermissionResponse>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        self.repo
            .grant_permission(&req.role_name, &req.permission_name)
            .await
            .map_err(|_| Status::internal("failed to grant permission"))?;
        self.audit(&md, "permission.grant", &req.role_name, &req.permission_name).await;
        Ok(Response::new(GrantPermissionResponse { success: true }))
    }

    async fn revoke_permission(
        &self,
        request: Request<RevokePermissionRequest>,
    ) -> Result<Response<RevokePermissionResponse>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        self.repo
            .revoke_permission(&req.role_name, &req.permission_name)
            .await
            .map_err(|_| Status::internal("failed to revoke permission"))?;
        self.audit(&md, "permission.revoke", &req.role_name, &req.permission_name).await;
        Ok(Response::new(RevokePermissionResponse { success: true }))
    }

    // ── Account recovery & verification (v0.2) ──────────────

    async fn request_email_verification(
        &self,
        request: Request<EmailRequest>,
    ) -> Result<Response<DevTokenResponse>, Status> {
        let req = request.into_inner();
        let mut resp = DevTokenResponse { success: true, dev_token: String::new() };
        let user = match self.repo.get_user_by_email(&req.email).await {
            Ok(Some(u)) => u,
            _ => return Ok(Response::new(resp)), // don't reveal existence
        };
        let token = gen_refresh_token();
        let exp = Utc::now() + Duration::hours(24);
        self.repo
            .create_email_verification(&hash_token(&token), user.id, exp)
            .await
            .map_err(|_| Status::internal("failed to create verification"))?;
        self.mail.send(&user.email, "Verify your email", &format!("Your email verification token: {token}"));
        self.audit_as(&user.id.to_string(), &user.email, "email.verification_requested", "", "").await;
        if !common::config::is_production() {
            resp.dev_token = token;
        }
        Ok(Response::new(resp))
    }

    async fn verify_email(
        &self,
        request: Request<TokenRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let uid = self
            .repo
            .consume_email_verification(&hash_token(&req.token))
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::invalid_argument("invalid or expired token"))?;
        self.repo
            .mark_email_verified(uid)
            .await
            .map_err(|_| Status::internal("failed to verify email"))?;
        self.audit_as(&uid.to_string(), "", "email.verified", "", "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    async fn request_password_reset(
        &self,
        request: Request<EmailRequest>,
    ) -> Result<Response<DevTokenResponse>, Status> {
        let req = request.into_inner();
        let mut resp = DevTokenResponse { success: true, dev_token: String::new() };
        let user = match self.repo.get_user_by_email(&req.email).await {
            Ok(Some(u)) => u,
            _ => return Ok(Response::new(resp)),
        };
        let token = gen_refresh_token();
        let exp = Utc::now() + Duration::hours(1);
        self.repo
            .create_password_reset(&hash_token(&token), user.id, exp)
            .await
            .map_err(|_| Status::internal("failed to create reset token"))?;
        self.mail.send(&user.email, "Reset your password", &format!("Your password reset token: {token}"));
        self.audit_as(&user.id.to_string(), &user.email, "password.reset_requested", "", "").await;
        if !common::config::is_production() {
            resp.dev_token = token;
        }
        Ok(Response::new(resp))
    }

    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        if req.new_password.len() < 8 {
            return Err(Status::invalid_argument("password must be at least 8 characters"));
        }
        let uid = self
            .repo
            .consume_password_reset(&hash_token(&req.token))
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::invalid_argument("invalid or expired token"))?;
        let hash = password::hash(&req.new_password).map_err(|_| Status::internal("failed to hash password"))?;
        self.repo
            .update_password(uid, &hash)
            .await
            .map_err(|_| Status::internal("failed to update password"))?;
        let _ = self.repo.revoke_all_user_refresh_tokens(uid).await;
        self.audit_as(&uid.to_string(), "", "password.reset", "", "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    // ── Audit (v0.2) ────────────────────────────────────────

    async fn list_audit_events(
        &self,
        request: Request<ListAuditEventsRequest>,
    ) -> Result<Response<ListAuditEventsResponse>, Status> {
        require_perm(request.metadata(), "audit:read")?;
        let req = request.into_inner();
        let mut limit = req.limit as i64;
        if limit <= 0 || limit > 200 {
            limit = 50;
        }
        let rows = self
            .repo
            .list_audit(limit)
            .await
            .map_err(|_| Status::internal("failed to list audit events"))?;
        let events = rows
            .into_iter()
            .map(|e| AuditEvent {
                id: e.id,
                actor_id: e.actor_id,
                actor_email: e.actor_email,
                action: e.action,
                target: e.target,
                detail: e.detail,
                created_at: e.created_at.to_rfc3339(),
            })
            .collect();
        Ok(Response::new(ListAuditEventsResponse { events }))
    }
}

fn gen_refresh_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
