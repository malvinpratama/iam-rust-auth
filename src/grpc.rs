//! Tonic implementation of AuthService.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
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

/// M6: the seeded default tenant every legacy/new identity belongs to until
/// explicitly enrolled elsewhere. Shared, fixed UUID across both stacks.
const DEFAULT_TENANT_ID: Uuid =
    Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// How long after a refresh token is rotated a concurrent re-presentation is
/// still treated as the benign parallel-refresh race (re-issue) rather than
/// theft (family wipe). Short enough to bound replay; long enough to absorb a
/// client firing several requests at once.
const REFRESH_ROTATION_GRACE_SECS: i64 = 60;

pub struct AuthSvc {
    repo: Repo,
    jwt: JwtManager,
    refresh_ttl_secs: i64,
    dummy_hash: String, // constant-time login on unknown users
    mail: Box<dyn Sender>,
    cache: crate::cache::Cache, // optional Redis: denylist + permission cache
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

/// Verify an RFC 7636 PKCE code_verifier against the stored challenge.
fn verify_pkce(challenge: &str, method: &str, verifier: &str) -> bool {
    match method {
        "S256" => URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge,
        "plain" | "" => verifier == challenge, // RFC 7636: default method is "plain"
        _ => false,
    }
}

impl AuthSvc {
    pub fn new(repo: Repo, jwt: JwtManager, refresh_ttl_secs: i64, mail: Box<dyn Sender>, cache: crate::cache::Cache) -> Self {
        let dummy_hash = password::hash("constant-time-dummy-password").unwrap_or_default();
        Self { repo, jwt, refresh_ttl_secs, dummy_hash, mail, cache }
    }

    /// Record a sensitive action with an explicit actor. `tenant` stamps the row
    /// so each organization's audit trail is isolated; `None` marks a pre-tenant
    /// or platform event (login/register/tenant-create) that no tenant view shows.
    async fn audit_as(&self, actor_id: &str, actor_email: &str, action: &str, target: &str, detail: &str, tenant: Option<Uuid>) {
        if common::config::audit_enabled() {
            let _ = self.repo.insert_audit(actor_id, actor_email, action, target, detail, tenant).await;
        }
    }

    /// Record a sensitive action with the actor + active tenant taken from gateway
    /// metadata (the tenant the caller's token is bound to).
    async fn audit(&self, md: &MetadataMap, action: &str, target: &str, detail: &str) {
        let actor_id = meta(md, "x-user-id");
        let actor_email = meta(md, "x-user-email");
        self.audit_as(&actor_id, &actor_email, action, target, detail, active_tenant(md).ok()).await;
    }

    /// M6: mint a token pair bound to a specific (tenant, project). The binding
    /// is carried in the access-token claims and persisted on the refresh row so
    /// a later Refresh keeps the same tenant/project.
    async fn issue_tokens(
        &self,
        user_id: Uuid,
        email: &str,
        tenant_id: Uuid,
        project_id: Option<Uuid>,
    ) -> Result<TokenPair, Status> {
        let proj_str = project_id.map(|p| p.to_string()).unwrap_or_default();
        let access = self
            .jwt
            .issue(&user_id.to_string(), email, &tenant_id.to_string(), &proj_str)
            .map_err(|_| Status::internal("failed to sign token"))?;
        let refresh = gen_refresh_token();
        let expires = Utc::now() + Duration::seconds(self.refresh_ttl_secs);
        self.repo
            .create_refresh_token(user_id, &hash_token(&refresh), expires, tenant_id, project_id)
            .await
            .map_err(|_| Status::internal("failed to persist refresh token"))?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: refresh,
            expires_in: self.jwt.access_ttl_secs(),
            token_type: "Bearer".into(),
            mfa_required: false,
            mfa_token: String::new(),
        })
    }

    /// M6: pick the user's active tenant (first active membership; default
    /// tenant as a fallback) and mint a tenant-wide token pair for it.
    async fn issue_for_active_tenant(&self, user_id: Uuid, email: &str) -> Result<TokenPair, Status> {
        let members = self
            .repo
            .list_memberships(user_id)
            .await
            .map_err(|_| Status::internal("failed to load memberships"))?;
        let tenant_id = members.first().map(|m| m.tenant_id).unwrap_or(DEFAULT_TENANT_ID);
        self.issue_tokens(user_id, email, tenant_id, None).await
    }

    /// M6: validate a role assignment for the active tenant — the role must be
    /// visible in the tenant (own role or built-in template) and any named
    /// project must belong to the tenant. Returns the parsed project id.
    async fn validate_assign(
        &self,
        role_name: &str,
        project_id: &str,
        tenant: Uuid,
    ) -> Result<Option<Uuid>, Status> {
        if !self
            .repo
            .role_in_tenant(role_name, tenant)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found in this tenant"));
        }
        let project = parse_opt_project(project_id)?;
        if let Some(pid) = project {
            if !self
                .repo
                .is_project_in_tenant(pid, tenant)
                .await
                .map_err(|_| Status::internal("db error"))?
            {
                return Err(Status::invalid_argument("project does not belong to this tenant"));
            }
        }
        Ok(project)
    }

    /// M6: a permission grant/revoke may only target the tenant's OWN role —
    /// built-in templates are platform-managed and shared across tenants.
    async fn perm_role_guard(&self, role_name: &str, tenant: Uuid) -> Result<(), Status> {
        if is_builtin_role(role_name) {
            return Err(Status::failed_precondition("cannot modify a built-in role's permissions"));
        }
        if !self
            .repo
            .tenant_role_exists(role_name, tenant)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found in this tenant"));
        }
        Ok(())
    }
}

/// Short-lived TTL for the token issued between the password and TOTP steps.
const MFA_TOKEN_TTL_SECS: i64 = 300;

/// Collect the caller's permissions from gateway metadata.
fn caller_perms(md: &MetadataMap) -> Vec<String> {
    meta(md, "x-user-permissions")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Parse the caller's user id from gateway metadata.
fn caller_uuid(md: &MetadataMap) -> Result<Uuid, Status> {
    Uuid::parse_str(&meta(md, "x-user-id"))
        .map_err(|_| Status::unauthenticated("missing or invalid caller identity"))
}

/// Built-in role templates (tenant_id IS NULL) shared across tenants — they are
/// platform-managed and must not be mutated from a tenant context.
fn is_builtin_role(name: &str) -> bool {
    name == "admin" || name == "user"
}

/// Parse an optional project id from a request field (empty = tenant-wide).
fn parse_opt_project(s: &str) -> Result<Option<Uuid>, Status> {
    if s.is_empty() {
        Ok(None)
    } else {
        Uuid::parse_str(s)
            .map(Some)
            .map_err(|_| Status::invalid_argument("invalid project id"))
    }
}

/// M6.4: the tenant the caller's token is bound to (forwarded by the gateway as
/// x-tenant-id). Tenant-scoped admin operations act within it.
fn active_tenant(md: &MetadataMap) -> Result<Uuid, Status> {
    let t = meta(md, "x-tenant-id");
    if t.is_empty() {
        return Err(Status::failed_precondition("no active tenant on token"));
    }
    Uuid::parse_str(&t).map_err(|_| Status::internal("invalid active tenant"))
}

#[tonic::async_trait]
impl AuthService for AuthSvc {
    // OIDC: public RS256 signing keys as a JWKS, for relying parties to verify tokens.
    #[tracing::instrument(skip_all)]
    async fn get_jwks(
        &self,
        _request: Request<GetJwksRequest>,
    ) -> Result<Response<GetJwksResponse>, Status> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT kid, public_pem FROM oidc_signing_keys")
                .fetch_all(&self.repo.pool)
                .await
                .map_err(|_| Status::internal("jwks query failed"))?;
        let mut keys = Vec::with_capacity(rows.len());
        for (kid, pem) in rows {
            let pk = RsaPublicKey::from_public_key_pem(&pem)
                .map_err(|_| Status::internal("invalid public key"))?;
            keys.push(Jwk {
                kid,
                kty: "RSA".to_string(),
                r#use: "sig".to_string(),
                alg: "RS256".to_string(),
                n: URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be()),
            });
        }
        Ok(Response::new(GetJwksResponse { keys }))
    }

    // ── OIDC Authorization Code + PKCE ──────────────────────

    #[tracing::instrument(skip_all)]
    async fn get_client(
        &self,
        request: Request<GetClientRequest>,
    ) -> Result<Response<OAuthClient>, Status> {
        let req = request.into_inner();
        let row = sqlx::query_as::<_, (String, String, Vec<String>, Vec<String>, Vec<String>, bool)>(
            "SELECT client_id, name, redirect_uris, scopes, grant_types, is_confidential \
             FROM oauth_clients WHERE client_id = $1",
        )
        .bind(&req.client_id)
        .fetch_optional(&self.repo.pool)
        .await
        .map_err(|_| Status::internal("client lookup failed"))?;
        match row {
            Some((client_id, name, redirect_uris, scopes, grant_types, is_confidential)) => {
                Ok(Response::new(OAuthClient {
                    client_id,
                    name,
                    redirect_uris,
                    scopes,
                    grant_types,
                    is_confidential,
                }))
            }
            None => Err(Status::not_found("client not found")),
        }
    }

    #[tracing::instrument(skip_all)]
    async fn create_authorization_code(
        &self,
        request: Request<CreateAuthorizationCodeRequest>,
    ) -> Result<Response<CreateAuthorizationCodeResponse>, Status> {
        let req = request.into_inner();
        let user_id =
            Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user id"))?;
        // Only mint a code for a member of the client's organization. The exchange
        // re-checks this, but gating at issuance means a non-member can't drive the
        // authorize/consent flow to a usable code at all.
        let client_tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM oauth_clients WHERE client_id = $1")
            .bind(&req.client_id)
            .fetch_optional(&self.repo.pool)
            .await
            .map_err(|_| Status::internal("client lookup failed"))?
            .ok_or_else(|| Status::not_found("client not found"))?;
        if !self
            .repo
            .is_active_member(user_id, client_tenant)
            .await
            .map_err(|_| Status::internal("membership check failed"))?
        {
            return Err(Status::permission_denied("not a member of this client's organization"));
        }
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let code = URL_SAFE_NO_PAD.encode(b);
        let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
        sqlx::query(
            "INSERT INTO oauth_authorization_codes \
             (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at) \
             VALUES ($1,$2,$3,$4,$5, NULLIF($6,''), NULLIF($7,''), NULLIF($8,''), now() + interval '5 minutes')",
        )
        .bind(&code_hash)
        .bind(&req.client_id)
        .bind(user_id)
        .bind(&req.redirect_uri)
        .bind(&req.scope)
        .bind(&req.code_challenge)
        .bind(&req.code_challenge_method)
        .bind(&req.nonce)
        .execute(&self.repo.pool)
        .await
        .map_err(|_| Status::internal("could not create authorization code"))?;
        Ok(Response::new(CreateAuthorizationCodeResponse { code }))
    }

    #[tracing::instrument(skip_all)]
    async fn get_consent(
        &self,
        request: Request<GetConsentRequest>,
    ) -> Result<Response<GetConsentResponse>, Status> {
        let req = request.into_inner();
        let user_id =
            Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user id"))?;
        let row: Option<(Vec<String>,)> =
            sqlx::query_as("SELECT scopes FROM oauth_consents WHERE user_id = $1 AND client_id = $2")
                .bind(user_id)
                .bind(&req.client_id)
                .fetch_optional(&self.repo.pool)
                .await
                .map_err(|_| Status::internal("consent lookup failed"))?;
        Ok(Response::new(GetConsentResponse {
            scopes: row.map(|r| r.0).unwrap_or_default(),
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn save_consent(
        &self,
        request: Request<SaveConsentRequest>,
    ) -> Result<Response<SaveConsentResponse>, Status> {
        let req = request.into_inner();
        let user_id =
            Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user id"))?;
        sqlx::query(
            "INSERT INTO oauth_consents (user_id, client_id, scopes) VALUES ($1,$2,$3) \
             ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now()",
        )
        .bind(user_id)
        .bind(&req.client_id)
        .bind(&req.scopes)
        .execute(&self.repo.pool)
        .await
        .map_err(|_| Status::internal("could not save consent"))?;
        Ok(Response::new(SaveConsentResponse { success: true }))
    }

    #[tracing::instrument(skip_all)]
    async fn exchange_authorization_code(
        &self,
        request: Request<ExchangeAuthorizationCodeRequest>,
    ) -> Result<Response<OidcTokenResponse>, Status> {
        let req = request.into_inner();
        let code_hash = hex::encode(Sha256::digest(req.code.as_bytes()));

        type CodeRow = (String, Uuid, String, String, Option<String>, Option<String>, Option<String>, bool, bool);
        let row: Option<CodeRow> = sqlx::query_as(
            "SELECT client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, used, (expires_at < now()) \
             FROM oauth_authorization_codes WHERE code_hash = $1",
        )
        .bind(&code_hash)
        .fetch_optional(&self.repo.pool)
        .await
        .map_err(|_| Status::internal("code lookup failed"))?;
        let (client_id, user_id, redirect_uri, scope, challenge, method, nonce, used, expired) =
            row.ok_or_else(|| Status::invalid_argument("invalid_grant"))?;
        if used || expired || client_id != req.client_id || redirect_uri != req.redirect_uri {
            return Err(Status::invalid_argument("invalid_grant"));
        }
        // Single-use: atomically claim the code (closes the check-then-set race).
        let claimed = sqlx::query("UPDATE oauth_authorization_codes SET used = true WHERE code_hash = $1 AND used = false")
            .bind(&code_hash)
            .execute(&self.repo.pool)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
        if claimed != 1 {
            return Err(Status::invalid_argument("invalid_grant"));
        }

        let has_pkce = challenge.as_deref().map(|c| !c.is_empty()).unwrap_or(false);
        if has_pkce
            && !verify_pkce(challenge.as_deref().unwrap_or(""), method.as_deref().unwrap_or("S256"), &req.code_verifier)
        {
            return Err(Status::invalid_argument("invalid_grant"));
        }

        let client: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT client_secret_hash, is_confidential FROM oauth_clients WHERE client_id = $1")
                .bind(&client_id)
                .fetch_optional(&self.repo.pool)
                .await
                .map_err(|_| Status::internal("client lookup failed"))?;
        let (secret_hash, is_confidential) =
            client.ok_or_else(|| Status::invalid_argument("invalid_client"))?;
        if is_confidential {
            let provided = hex::encode(Sha256::digest(req.client_secret.as_bytes()));
            if secret_hash.as_deref() != Some(provided.as_str()) {
                return Err(Status::unauthenticated("invalid_client"));
            }
        } else if !has_pkce {
            return Err(Status::invalid_argument("PKCE required for public clients"));
        }

        let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&self.repo.pool)
            .await
            .map_err(|_| Status::internal("user lookup failed"))?;

        // M6.5: bind the session to the OIDC client's tenant — the client
        // identifies the organization this app serves; the user must be a member.
        let client_tenant: Uuid =
            sqlx::query_scalar("SELECT tenant_id FROM oauth_clients WHERE client_id = $1")
                .bind(&client_id)
                .fetch_one(&self.repo.pool)
                .await
                .map_err(|_| Status::internal("client tenant lookup failed"))?;
        if !self
            .repo
            .is_active_member(user_id, client_tenant)
            .await
            .map_err(|_| Status::internal("membership check failed"))?
        {
            return Err(Status::permission_denied("not a member of this organization"));
        }
        let tp = self.issue_tokens(user_id, &email, client_tenant, None).await?;
        let issuer = common::env_or("OIDC_ISSUER", "http://localhost:8080");
        let id_token = self
            .jwt
            .issue_id_token(&user_id.to_string(), &email, &client_id, nonce.as_deref().unwrap_or(""), &issuer)
            .map_err(|_| Status::internal("failed to sign id_token"))?;
        Ok(Response::new(OidcTokenResponse {
            access_token: tp.access_token,
            id_token,
            refresh_token: tp.refresh_token,
            expires_in: tp.expires_in,
            token_type: "Bearer".to_string(),
            scope,
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn register_client(
        &self,
        request: Request<RegisterClientRequest>,
    ) -> Result<Response<RegisterClientResponse>, Status> {
        require_perm(request.metadata(), "role:write")?; // defense-in-depth (gateway also gates)
        // M6.5: the new client belongs to the caller's active tenant.
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        let client_id = Uuid::new_v4().to_string();
        let (secret, secret_hash) = if req.is_confidential {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            let s = URL_SAFE_NO_PAD.encode(b);
            let h = hex::encode(Sha256::digest(s.as_bytes()));
            (s, Some(h))
        } else {
            (String::new(), None)
        };
        let scopes = if req.scopes.is_empty() {
            vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
        } else {
            req.scopes
        };
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, grant_types, is_confidential, tenant_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(&client_id)
        .bind(&secret_hash)
        .bind(&req.name)
        .bind(&req.redirect_uris)
        .bind(&scopes)
        .bind(vec!["authorization_code".to_string(), "refresh_token".to_string()])
        .bind(req.is_confidential)
        .bind(tenant)
        .execute(&self.repo.pool)
        .await
        .map_err(|_| Status::internal("could not register client"))?;
        Ok(Response::new(RegisterClientResponse { client_id, client_secret: secret }))
    }

    #[tracing::instrument(skip_all)]
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
        // M6: enroll the new identity into the default tenant so it has a home
        // organization (user_roles already default to it; this makes the
        // membership explicit for /me/memberships and the switcher).
        let _ = self.repo.create_membership(id, DEFAULT_TENANT_ID).await;
        self.audit_as(&id.to_string(), &req.email, "user.register", "", "", None).await;
        Ok(Response::new(RegisterResponse {
            user_id: id.to_string(),
            email: req.email,
        }))
    }

    #[tracing::instrument(skip_all)]
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
                        self.audit_as(&user.id.to_string(), &user.email, "login.locked", "", "too many failed attempts", None).await;
                    }
                }
            }
            self.audit_as(&user.id.to_string(), &user.email, "login.failure", "", "", None).await;
            return Err(Status::unauthenticated("invalid credentials"));
        }

        if common::config::require_email_verification() && !user.email_verified {
            return Err(Status::unauthenticated("email not verified"));
        }

        // Soft-deleted identities cannot log in (reported as invalid credentials).
        if user.deleted_at.is_some() {
            return Err(Status::unauthenticated("invalid credentials"));
        }

        let _ = self.repo.reset_login_state(user.id).await;

        // 2FA: when TOTP is enabled, issue a short-lived MFA token; the client
        // completes login via LoginTotp with a TOTP or recovery code.
        if user.totp_enabled {
            self.audit_as(&user.id.to_string(), &user.email, "login.mfa_challenge", "", "", None).await;
            let mfa = self
                .jwt
                .issue_mfa(&user.id.to_string(), MFA_TOKEN_TTL_SECS)
                .map_err(|_| Status::internal("failed to issue mfa token"))?;
            return Ok(Response::new(TokenPair {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_in: 0,
                token_type: "Bearer".into(),
                mfa_required: true,
                mfa_token: mfa,
            }));
        }

        self.audit_as(&user.id.to_string(), &user.email, "login.success", "", "", None).await;
        let pair = self.issue_for_active_tenant(user.id, &user.email).await?;
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
        if let Some(revoked_at) = row.revoked_at {
            // A token revoked by *rotation* (replaced_by set) re-presented within
            // the grace window is the benign concurrent-refresh race (e.g. NextAuth
            // firing several requests after the access token expires) — re-issue
            // instead of treating it as theft.
            let rotated = row.replaced_by.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
            if rotated && (Utc::now() - revoked_at) < Duration::seconds(REFRESH_ROTATION_GRACE_SECS) {
                let user = self
                    .repo
                    .get_user_by_id(row.user_id)
                    .await
                    .map_err(|_| Status::internal("db error"))?
                    .ok_or_else(|| Status::unauthenticated("user not found"))?;
                let pair = self
                    .issue_tokens(user.id, &user.email, row.tenant_id, row.project_id)
                    .await?;
                return Ok(Response::new(pair));
            }
            // Otherwise (logout-revoked, or rotated outside the grace) genuine reuse
            // suggests theft → revoke the whole token family.
            let _ = self.repo.revoke_all_user_refresh_tokens(row.user_id).await;
            self.audit_as(&row.user_id.to_string(), "", "refresh.reuse_detected", "", "all sessions revoked", None).await;
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
        // Rotate: issue the fresh pair (keeping the tenant/project binding), then
        // mark the presented token rotated and point it at its successor so a
        // concurrent re-presentation hits the grace path above, not the family wipe.
        let pair = self
            .issue_tokens(user.id, &user.email, row.tenant_id, row.project_id)
            .await?;
        let successor = hash_token(&pair.refresh_token);
        let _ = self.repo.rotate_refresh_token(&hash, &successor).await;
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
                // Mirror into the Redis denylist so other replicas reject it now.
                self.cache.deny(&claims.jti, claims.exp - Utc::now().timestamp()).await;
            }
        }
        self.audit(&md, "auth.logout", "", "").await;
        Ok(Response::new(LogoutResponse { success: true }))
    }

    #[tracing::instrument(skip_all)]
    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();
        let claims = self
            .jwt
            .parse(&req.access_token)
            .map_err(|_| Status::unauthenticated("invalid or expired token"))?;
        // An MFA-purpose token only completes a 2FA login; never a bearer token.
        if !claims.purpose.is_empty() {
            return Err(Status::unauthenticated("invalid token"));
        }
        // Prefer the Redis denylist (shared across replicas); fall back to the
        // durable Postgres denylist when Redis is off or errors.
        let denied = match self.cache.is_denied(&claims.jti).await {
            Some(d) => d,
            None => self
                .repo
                .is_token_revoked(&claims.jti)
                .await
                .map_err(|_| Status::internal("failed to check token status"))?,
        };
        if denied {
            return Err(Status::unauthenticated("token revoked"));
        }
        let user_id =
            Uuid::parse_str(&claims.sub).map_err(|_| Status::unauthenticated("invalid subject"))?;
        // Reject tokens for a soft-deleted (or removed) identity.
        if !self
            .repo
            .is_user_active(user_id)
            .await
            .map_err(|_| Status::internal("failed to check account status"))?
        {
            return Err(Status::unauthenticated("account is not active"));
        }
        // M6: resolve the token's tenant/project once. A tenant-bound token is
        // only valid while the user is still an active member (revoking
        // membership logs them out), and RBAC is scoped to that tenant/project.
        let tenant_uuid = if claims.tenant_id.is_empty() {
            None
        } else {
            let tid = Uuid::parse_str(&claims.tenant_id)
                .map_err(|_| Status::unauthenticated("invalid tenant claim"))?;
            if !self
                .repo
                .is_active_member(user_id, tid)
                .await
                .map_err(|_| Status::internal("failed to check membership"))?
            {
                return Err(Status::unauthenticated("tenant membership revoked"));
            }
            Some(tid)
        };
        let project_uuid = if claims.project_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&claims.project_id)
                    .map_err(|_| Status::unauthenticated("invalid project claim"))?,
            )
        };
        // M6.3: roles/permissions scoped to the token's tenant (+ optional
        // project) — the same user can hold different roles in different
        // tenants. A token without a tenant falls back to the global view.
        let roles = match tenant_uuid {
            Some(tid) => self
                .repo
                .get_user_roles_scoped(user_id, tid, project_uuid)
                .await
                .map_err(|_| Status::internal("failed to load roles"))?,
            None => self
                .repo
                .get_user_roles(user_id)
                .await
                .map_err(|_| Status::internal("failed to load roles"))?,
        };
        // Permission cache (Redis, short TTL) cuts the RBAC join off the hot
        // path of every authenticated request; misses fall back to Postgres.
        // The key is scoped to tenant/project so a switch can't read stale perms.
        let permissions = match self
            .cache
            .get_perms(&claims.tenant_id, &claims.project_id, &claims.sub)
            .await
        {
            Some(p) => p,
            None => {
                let p = match tenant_uuid {
                    Some(tid) => self
                        .repo
                        .get_user_permissions_scoped(user_id, tid, project_uuid)
                        .await
                        .map_err(|_| Status::internal("failed to load permissions"))?,
                    None => self
                        .repo
                        .get_user_permissions(user_id)
                        .await
                        .map_err(|_| Status::internal("failed to load permissions"))?,
                };
                self.cache
                    .set_perms(&claims.tenant_id, &claims.project_id, &claims.sub, &p)
                    .await;
                p
            }
        };
        Ok(Response::new(ValidateTokenResponse {
            user_id: claims.sub,
            email: claims.email,
            roles,
            permissions,
            tenant_id: claims.tenant_id,
            project_id: claims.project_id,
        }))
    }

    // M6: tenants the caller is an active member of (drives the console switcher).
    #[tracing::instrument(skip_all)]
    async fn list_my_memberships(
        &self,
        request: Request<ListMembershipsRequest>,
    ) -> Result<Response<ListMembershipsResponse>, Status> {
        let caller = caller_uuid(request.metadata())?;
        let rows = self
            .repo
            .list_memberships(caller)
            .await
            .map_err(|_| Status::internal("failed to load memberships"))?;
        let memberships = rows
            .into_iter()
            .map(|m| Membership {
                tenant_id: m.tenant_id.to_string(),
                tenant_slug: m.tenant_slug,
                tenant_name: m.tenant_name,
                status: m.status,
            })
            .collect();
        Ok(Response::new(ListMembershipsResponse { memberships }))
    }

    // M6: re-issue a fresh token pair bound to another tenant/project the caller
    // belongs to, without revoking the current one (concurrent sessions).
    #[tracing::instrument(skip_all)]
    async fn switch_tenant(
        &self,
        request: Request<SwitchTenantRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        let caller = caller_uuid(request.metadata())?;
        let req = request.into_inner();
        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|_| Status::invalid_argument("invalid tenant id"))?;
        if !self
            .repo
            .is_active_member(caller, tenant_id)
            .await
            .map_err(|_| Status::internal("failed to check membership"))?
        {
            return Err(Status::permission_denied("not a member of that tenant"));
        }
        let project_id = if req.project_id.is_empty() {
            None
        } else {
            let pid = Uuid::parse_str(&req.project_id)
                .map_err(|_| Status::invalid_argument("invalid project id"))?;
            // The project must belong to the tenant being switched into, else the
            // re-issued token would carry a cross-tenant project_id claim.
            if !self
                .repo
                .is_project_in_tenant(pid, tenant_id)
                .await
                .map_err(|_| Status::internal("project check failed"))?
            {
                return Err(Status::invalid_argument("project does not belong to this tenant"));
            }
            Some(pid)
        };
        let user = self
            .repo
            .get_user_by_id(caller)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::unauthenticated("user not found"))?;
        let pair = self.issue_tokens(caller, &user.email, tenant_id, project_id).await?;
        Ok(Response::new(pair))
    }

    // ── M6.4: tenant / project / member administration ──────────

    #[tracing::instrument(skip_all)]
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<Tenant>, Status> {
        require_perm(request.metadata(), "tenant:write")?;
        let caller = caller_uuid(request.metadata())?;
        let req = request.into_inner();
        if req.slug.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument("slug and name are required"));
        }
        let t = self
            .repo
            .create_tenant_with_admin(&req.slug, &req.name, caller)
            .await
            .map_err(|_| Status::already_exists("tenant slug already taken"))?;
        self.audit_as(&caller.to_string(), "", "tenant.create", &t.id.to_string(), &req.slug, None).await;
        Ok(Response::new(Tenant { id: t.id.to_string(), slug: t.slug, name: t.name, status: t.status }))
    }

    #[tracing::instrument(skip_all)]
    async fn list_tenants(
        &self,
        request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        require_perm(request.metadata(), "tenant:read")?;
        let rows = self
            .repo
            .list_tenants()
            .await
            .map_err(|_| Status::internal("failed to list tenants"))?;
        let tenants = rows
            .into_iter()
            .map(|t| Tenant { id: t.id.to_string(), slug: t.slug, name: t.name, status: t.status })
            .collect();
        Ok(Response::new(ListTenantsResponse { tenants }))
    }

    #[tracing::instrument(skip_all)]
    async fn create_project(
        &self,
        request: Request<CreateProjectRequest>,
    ) -> Result<Response<Project>, Status> {
        require_perm(request.metadata(), "project:write")?;
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        if req.slug.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument("slug and name are required"));
        }
        let p = self
            .repo
            .create_project(tenant, &req.slug, &req.name)
            .await
            .map_err(|_| Status::already_exists("project slug already taken in this tenant"))?;
        Ok(Response::new(Project {
            id: p.id.to_string(),
            tenant_id: p.tenant_id.to_string(),
            slug: p.slug,
            name: p.name,
        }))
    }

    #[tracing::instrument(skip_all)]
    async fn list_projects(
        &self,
        request: Request<ListProjectsRequest>,
    ) -> Result<Response<ListProjectsResponse>, Status> {
        require_perm(request.metadata(), "project:read")?;
        let tenant = active_tenant(request.metadata())?;
        let rows = self
            .repo
            .list_projects_by_tenant(tenant)
            .await
            .map_err(|_| Status::internal("failed to list projects"))?;
        let projects = rows
            .into_iter()
            .map(|p| Project {
                id: p.id.to_string(),
                tenant_id: p.tenant_id.to_string(),
                slug: p.slug,
                name: p.name,
            })
            .collect();
        Ok(Response::new(ListProjectsResponse { projects }))
    }

    #[tracing::instrument(skip_all)]
    async fn add_member(
        &self,
        request: Request<AddMemberRequest>,
    ) -> Result<Response<Member>, Status> {
        require_perm(request.metadata(), "member:write")?;
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        let user = self
            .repo
            .get_user_by_email(&req.email)
            .await
            .map_err(|_| Status::internal("user lookup failed"))?
            .ok_or_else(|| Status::not_found("no user with that email"))?;
        self.repo
            .add_member(user.id, tenant)
            .await
            .map_err(|_| Status::internal("could not add member"))?;
        self.audit_as(&user.id.to_string(), &user.email, "member.add", &tenant.to_string(), "", Some(tenant)).await;
        Ok(Response::new(Member { user_id: user.id.to_string(), email: user.email, status: "active".into() }))
    }

    #[tracing::instrument(skip_all)]
    async fn remove_member(
        &self,
        request: Request<RemoveMemberRequest>,
    ) -> Result<Response<RemoveMemberResponse>, Status> {
        require_perm(request.metadata(), "member:write")?;
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        let uid = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        self.repo
            .remove_member(uid, tenant)
            .await
            .map_err(|_| Status::internal("could not remove member"))?;
        self.audit_as(&req.user_id, "", "member.remove", &tenant.to_string(), "", Some(tenant)).await;
        Ok(Response::new(RemoveMemberResponse { success: true }))
    }

    #[tracing::instrument(skip_all)]
    async fn list_members(
        &self,
        request: Request<ListMembersRequest>,
    ) -> Result<Response<ListMembersResponse>, Status> {
        require_perm(request.metadata(), "member:read")?;
        let tenant = active_tenant(request.metadata())?;
        let rows = self
            .repo
            .list_members_by_tenant(tenant)
            .await
            .map_err(|_| Status::internal("failed to list members"))?;
        let members = rows
            .into_iter()
            .map(|m| Member { user_id: m.user_id.to_string(), email: m.email, status: m.status })
            .collect();
        Ok(Response::new(ListMembersResponse { members }))
    }

    #[tracing::instrument(skip_all)]
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
            hard: req.hard,
        })
        .map_err(|_| Status::internal("failed to encode event"))?;
        self.repo
            .delete_user_event_soft(user_id, req.hard, common::events::TYPE_USER_DELETED, &payload)
            .await
            .map_err(|_| Status::internal("failed to delete user"))?;
        self.audit(&md, "user.delete", &req.user_id, if req.hard { "hard" } else { "soft" }).await;
        Ok(Response::new(DeleteUserResponse { success: true }))
    }

    // ── 2FA / TOTP (v0.9) ──

    async fn enroll_totp(
        &self,
        request: Request<EnrollTotpRequest>,
    ) -> Result<Response<EnrollTotpResponse>, Status> {
        let md = request.metadata().clone();
        let uid = caller_uuid(&md)?;
        let user = self
            .repo
            .get_user_by_id(uid)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("user not found"))?;
        // Re-enrolling would reset the secret and silently disable working 2FA;
        // require an explicit disable first.
        if user.totp_enabled {
            return Err(Status::failed_precondition("2FA is already enabled; disable it first"));
        }
        let secret = crate::totp::generate(&user.email).ok_or_else(|| Status::internal("failed to generate secret"))?;
        let recovery = crate::totp::generate_recovery_codes(10);
        self.repo
            .set_totp_secret(uid, &secret.base32)
            .await
            .map_err(|_| Status::internal("failed to store secret"))?;
        let _ = self.repo.delete_recovery_codes(uid).await;
        for c in &recovery {
            self.repo
                .insert_recovery_code(uid, &hash_token(c))
                .await
                .map_err(|_| Status::internal("failed to store recovery code"))?;
        }
        self.audit(&md, "totp.enroll", "", "").await;
        Ok(Response::new(EnrollTotpResponse {
            secret: secret.base32,
            otpauth_uri: secret.otpauth_uri,
            recovery_codes: recovery,
        }))
    }

    async fn get_totp_status(
        &self,
        request: Request<GetTotpStatusRequest>,
    ) -> Result<Response<GetTotpStatusResponse>, Status> {
        let uid = caller_uuid(request.metadata())?;
        let user = self
            .repo
            .get_user_by_id(uid)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("user not found"))?;
        Ok(Response::new(GetTotpStatusResponse { enabled: user.totp_enabled }))
    }

    async fn activate_totp(
        &self,
        request: Request<ActivateTotpRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let md = request.metadata().clone();
        let uid = caller_uuid(&md)?;
        let req = request.into_inner();
        let user = self
            .repo
            .get_user_by_id(uid)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("user not found"))?;
        let secret = user.totp_secret.ok_or_else(|| Status::failed_precondition("no pending enrollment; call EnrollTotp first"))?;
        if !crate::totp::validate(&req.code, &secret) {
            return Err(Status::unauthenticated("invalid code"));
        }
        self.repo.enable_totp(uid).await.map_err(|_| Status::internal("failed to enable 2FA"))?;
        self.audit(&md, "totp.activate", "", "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    async fn disable_totp(
        &self,
        request: Request<DisableTotpRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let md = request.metadata().clone();
        let uid = caller_uuid(&md)?;
        let req = request.into_inner();
        let user = self
            .repo
            .get_user_by_id(uid)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("user not found"))?;
        if !user.totp_enabled {
            return Ok(Response::new(GenericResponse { success: true }));
        }
        let ok = user.totp_secret.as_deref().map(|s| crate::totp::validate(&req.code, s)).unwrap_or(false);
        let ok = ok
            || self
                .repo
                .consume_recovery_code(uid, &hash_token(&req.code))
                .await
                .map_err(|_| Status::internal("db error"))?;
        if !ok {
            return Err(Status::unauthenticated("invalid code"));
        }
        self.repo.disable_totp(uid).await.map_err(|_| Status::internal("failed to disable 2FA"))?;
        let _ = self.repo.delete_recovery_codes(uid).await;
        self.audit(&md, "totp.disable", "", "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    async fn login_totp(
        &self,
        request: Request<LoginTotpRequest>,
    ) -> Result<Response<TokenPair>, Status> {
        let req = request.into_inner();
        let claims = self
            .jwt
            .parse(&req.mfa_token)
            .map_err(|_| Status::unauthenticated("invalid or expired mfa token"))?;
        if claims.purpose != "mfa" {
            return Err(Status::unauthenticated("invalid mfa token"));
        }
        let uid = Uuid::parse_str(&claims.sub).map_err(|_| Status::unauthenticated("invalid mfa token"))?;
        let user = self
            .repo
            .get_user_by_id(uid)
            .await
            .map_err(|_| Status::internal("db error"))?
            .filter(|u| u.deleted_at.is_none() && u.totp_enabled && u.totp_secret.is_some())
            .ok_or_else(|| Status::unauthenticated("invalid credentials"))?;
        // The MFA step is brute-forceable (6-digit TOTP / recovery codes) within
        // the MFA token's TTL, so it gets the same lockout as the password step.
        if let Some(until) = user.locked_until {
            if until > Utc::now() {
                return Err(Status::unauthenticated("account temporarily locked, try again later"));
            }
        }
        let secret = user.totp_secret.clone().unwrap();
        let ok = crate::totp::validate(&req.code, &secret)
            || self
                .repo
                .consume_recovery_code(uid, &hash_token(&req.code))
                .await
                .map_err(|_| Status::internal("db error"))?;
        if !ok {
            let max = common::config::login_max_failures();
            if max > 0 {
                if let Ok(n) = self.repo.increment_login_failure(uid).await {
                    if (n as i64) >= max {
                        let until = Utc::now() + Duration::seconds(common::config::login_lockout_secs());
                        let _ = self.repo.lock_user(uid, until).await;
                        self.audit_as(&uid.to_string(), &user.email, "login.locked", "", "too many failed mfa attempts", None).await;
                    }
                }
            }
            self.audit_as(&uid.to_string(), &user.email, "login.mfa_failure", "", "", None).await;
            return Err(Status::unauthenticated("invalid code"));
        }
        let _ = self.repo.reset_login_state(uid).await; // clear failure counter on success
        self.audit_as(&uid.to_string(), &user.email, "login.success", "", "2fa", None).await;
        let pair = self.issue_for_active_tenant(uid, &user.email).await?;
        Ok(Response::new(pair))
    }

    // ── API keys (v0.9) ──

    async fn create_api_key(
        &self,
        request: Request<CreateApiKeyRequest>,
    ) -> Result<Response<CreateApiKeyResponse>, Status> {
        let md = request.metadata().clone();
        let uid = caller_uuid(&md)?;
        let perms = caller_perms(&md);
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        for s in &req.scopes {
            if !perms.iter().any(|p| p == s) {
                return Err(Status::permission_denied(format!("cannot grant a scope you do not hold: {s}")));
            }
        }
        let key_id = gen_hex(8);
        let secret = gen_hex(24);
        let full = format!("iamk_{key_id}_{secret}");
        let expires = if req.ttl_seconds > 0 {
            Some(Utc::now() + Duration::seconds(req.ttl_seconds))
        } else {
            None
        };
        // Bind the key to the tenant (+ optional project) it is minted in, so its
        // effective permissions can never exceed the owner's access in that tenant.
        let tenant = active_tenant(&md)?;
        let project = parse_opt_project(&meta(&md, "x-project-id"))?;
        self.repo
            .create_api_key(&key_id, uid, &hash_token(&full), &req.name, &req.scopes, expires, tenant, project)
            .await
            .map_err(|_| Status::internal("failed to create api key"))?;
        self.audit(&md, "apikey.create", &key_id, &req.name).await;
        Ok(Response::new(CreateApiKeyResponse {
            secret: full,
            key: Some(ApiKey {
                id: key_id,
                name: req.name,
                scopes: req.scopes,
                created_at: Utc::now().to_rfc3339(),
                expires_at: expires.map(|t| t.to_rfc3339()).unwrap_or_default(),
                last_used_at: String::new(),
            }),
        }))
    }

    async fn list_api_keys(
        &self,
        request: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        let uid = caller_uuid(request.metadata())?;
        let rows = self.repo.list_api_keys(uid).await.map_err(|_| Status::internal("failed to list api keys"))?;
        let keys = rows
            .into_iter()
            .map(|r| ApiKey {
                id: r.id,
                name: r.name,
                scopes: r.scopes,
                created_at: r.created_at.to_rfc3339(),
                expires_at: r.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                last_used_at: r.last_used_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(ListApiKeysResponse { keys }))
    }

    async fn revoke_api_key(
        &self,
        request: Request<RevokeApiKeyRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let md = request.metadata().clone();
        let uid = caller_uuid(&md)?;
        let req = request.into_inner();
        self.repo
            .revoke_api_key(&req.id, uid)
            .await
            .map_err(|_| Status::internal("failed to revoke api key"))?;
        self.audit(&md, "apikey.revoke", &req.id, "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    async fn validate_api_key(
        &self,
        request: Request<ValidateApiKeyRequest>,
    ) -> Result<Response<ValidateApiKeyResponse>, Status> {
        let req = request.into_inner();
        let row = self
            .repo
            .get_api_key_by_hash(&hash_token(&req.api_key))
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::unauthenticated("invalid api key"))?;
        if row.revoked_at.is_some() {
            return Err(Status::unauthenticated("api key revoked"));
        }
        if let Some(exp) = row.expires_at {
            if exp < Utc::now() {
                return Err(Status::unauthenticated("api key expired"));
            }
        }
        let user = self
            .repo
            .get_user_by_id(row.user_id)
            .await
            .map_err(|_| Status::internal("db error"))?
            .filter(|u| u.deleted_at.is_none())
            .ok_or_else(|| Status::unauthenticated("invalid api key"))?;
        // The key only carries the permissions its owner still holds in the tenant
        // it was minted in; if that membership (or tenant) was deactivated the key
        // is dead. This stops a key from granting cross-tenant or stale access.
        let member = self
            .repo
            .is_active_member(row.user_id, row.tenant_id)
            .await
            .map_err(|_| Status::internal("db error"))?;
        if !member {
            return Err(Status::unauthenticated("api key tenant membership revoked"));
        }
        // Effective scopes = key scopes ∩ the owner's permissions in that tenant.
        let perms = self
            .repo
            .get_user_permissions_scoped(row.user_id, row.tenant_id, row.project_id)
            .await
            .map_err(|_| Status::internal("failed to load permissions"))?;
        let scopes: Vec<String> = row.scopes.into_iter().filter(|s| perms.contains(s)).collect();
        let _ = self.repo.touch_api_key(&row.id).await;
        Ok(Response::new(ValidateApiKeyResponse {
            user_id: row.user_id.to_string(),
            email: user.email,
            scopes,
        }))
    }

    // ── Soft-delete restore (v0.9) ──

    async fn restore_user(
        &self,
        request: Request<RestoreUserRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        require_perm(request.metadata(), "user:delete")?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("invalid user id"))?;
        let payload = serde_json::to_string(&common::events::UserRestored { user_id: req.user_id.clone() })
            .map_err(|_| Status::internal("failed to encode event"))?;
        self.repo
            .restore_user_event(user_id, common::events::TYPE_USER_RESTORED, &payload)
            .await
            .map_err(|_| Status::internal("failed to restore user"))?;
        self.audit(&md, "user.restore", &req.user_id, "").await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<Role>, Status> {
        require_perm(request.metadata(), "role:write")?;
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("role name is required"));
        }
        if is_builtin_role(&req.name) {
            return Err(Status::failed_precondition("name reserved for a built-in role"));
        }
        let role = self
            .repo
            .create_role(&req.name, &req.description, tenant)
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
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        if is_builtin_role(&req.name) {
            return Err(Status::failed_precondition("cannot modify a built-in role"));
        }
        let role = self
            .repo
            .update_role(&req.name, &req.description, tenant)
            .await
            .map_err(|_| Status::internal("db error"))?
            .ok_or_else(|| Status::not_found("role not found in this tenant"))?;
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
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        if is_builtin_role(&req.name) {
            return Err(Status::failed_precondition("cannot delete a built-in role"));
        }
        if !self
            .repo
            .tenant_role_exists(&req.name, tenant)
            .await
            .map_err(|_| Status::internal("db error"))?
        {
            return Err(Status::not_found("role not found in this tenant"));
        }
        self.repo
            .delete_role(&req.name, tenant)
            .await
            .map_err(|_| Status::internal("failed to delete role"))?;
        self.audit(&md, "role.delete", &req.name, "").await;
        Ok(Response::new(DeleteRoleResponse { success: true }))
    }

    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        require_perm(request.metadata(), "role:read")?;
        let tenant = active_tenant(request.metadata())?;
        // The tenant's own roles + shared built-in templates, aggregated — no N+1.
        let rows = self
            .repo
            .list_roles_with_permissions(tenant)
            .await
            .map_err(|_| Status::internal("failed to list roles"))?;
        let roles = rows
            .into_iter()
            .map(|r| Role {
                id: r.id,
                name: r.name,
                description: r.description,
                permissions: r.permissions,
            })
            .collect();
        Ok(Response::new(ListRolesResponse { roles }))
    }

    async fn assign_role(
        &self,
        request: Request<AssignRoleRequest>,
    ) -> Result<Response<AssignRoleResponse>, Status> {
        require_perm(request.metadata(), "role:assign")?;
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        let project = self.validate_assign(&req.role_name, &req.project_id, tenant).await?;
        self.repo
            .assign_role(user_id, &req.role_name, tenant, project)
            .await
            .map_err(|_| Status::internal("failed to assign role"))?;
        self.cache.invalidate_perms(&req.user_id).await;
        self.audit(&md, "role.assign", &req.user_id, &req.role_name).await;
        Ok(Response::new(AssignRoleResponse { success: true }))
    }

    async fn assign_role_bulk(
        &self,
        request: Request<AssignRoleBulkRequest>,
    ) -> Result<Response<AssignRoleBulkResponse>, Status> {
        require_perm(request.metadata(), "role:assign")?;
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        let project = self.validate_assign(&req.role_name, &req.project_id, tenant).await?;
        let mut assigned = 0i32;
        let mut failed = Vec::new();
        for uid in &req.user_ids {
            match Uuid::parse_str(uid) {
                Ok(user_id) => match self.repo.assign_role(user_id, &req.role_name, tenant, project).await {
                    Ok(_) => {
                        self.cache.invalidate_perms(uid).await;
                        assigned += 1;
                    }
                    Err(_) => failed.push(uid.clone()),
                },
                Err(_) => failed.push(uid.clone()),
            }
        }
        self.audit(&md, "role.assign_bulk", &req.role_name, &format!("{assigned} assigned, {} failed", failed.len())).await;
        Ok(Response::new(AssignRoleBulkResponse { assigned, failed }))
    }

    async fn revoke_role(
        &self,
        request: Request<RevokeRoleRequest>,
    ) -> Result<Response<RevokeRoleResponse>, Status> {
        require_perm(request.metadata(), "role:assign")?;
        let tenant = active_tenant(request.metadata())?;
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
        let project = parse_opt_project(&req.project_id)?;
        self.repo
            .revoke_role(user_id, &req.role_name, tenant, project)
            .await
            .map_err(|_| Status::internal("failed to revoke role"))?;
        self.cache.invalidate_perms(&req.user_id).await;
        self.audit(&md, "role.revoke", &req.user_id, &req.role_name).await;
        Ok(Response::new(RevokeRoleResponse { success: true }))
    }

    // M6: a user's role assignments in the active tenant (role + project scope).
    async fn get_user_role_assignments(
        &self,
        request: Request<GetUserRoleAssignmentsRequest>,
    ) -> Result<Response<GetUserRoleAssignmentsResponse>, Status> {
        require_perm(request.metadata(), "role:read")?;
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user id"))?;
        let rows = self
            .repo
            .get_user_role_assignments(user_id, tenant)
            .await
            .map_err(|_| Status::internal("failed to load role assignments"))?;
        let assignments = rows
            .into_iter()
            .map(|r| RoleAssignment {
                role: r.role,
                project_id: r.project_id.map(|p| p.to_string()).unwrap_or_default(),
                project_slug: r.project_slug.unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(GetUserRoleAssignmentsResponse { assignments }))
    }

    async fn list_permissions(
        &self,
        request: Request<ListPermissionsRequest>,
    ) -> Result<Response<ListPermissionsResponse>, Status> {
        require_perm(request.metadata(), "role:read")?;
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
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        self.perm_role_guard(&req.role_name, tenant).await?;
        self.repo
            .grant_permission(&req.role_name, &req.permission_name, tenant)
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
        let tenant = active_tenant(request.metadata())?;
        let md = request.metadata().clone();
        let req = request.into_inner();
        self.perm_role_guard(&req.role_name, tenant).await?;
        self.repo
            .revoke_permission(&req.role_name, &req.permission_name, tenant)
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
        self.audit_as(&user.id.to_string(), &user.email, "email.verification_requested", "", "", None).await;
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
        self.audit_as(&uid.to_string(), "", "email.verified", "", "", None).await;
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
        self.audit_as(&user.id.to_string(), &user.email, "password.reset_requested", "", "", None).await;
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
        self.audit_as(&uid.to_string(), "", "password.reset", "", "", None).await;
        Ok(Response::new(GenericResponse { success: true }))
    }

    // ── Audit (v0.2) ────────────────────────────────────────

    async fn list_audit_events(
        &self,
        request: Request<ListAuditEventsRequest>,
    ) -> Result<Response<ListAuditEventsResponse>, Status> {
        require_perm(request.metadata(), "audit:read")?;
        let tenant = active_tenant(request.metadata())?;
        let req = request.into_inner();
        let mut limit = req.limit as i64;
        if limit <= 0 || limit > 200 {
            limit = 50;
        }
        let rows = self
            .repo
            .list_audit(tenant, limit)
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

fn gen_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
