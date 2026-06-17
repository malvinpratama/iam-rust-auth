mod cache;
mod grpc;
mod keys;
mod relay;
mod repo;
mod saga;
mod totp;
mod totpsecret;

use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;

use common::config::JwtConfig;
use proto::auth::v1::auth_service_server::AuthServiceServer;

use crate::grpc::AuthSvc;
use crate::repo::Repo;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::telemetry::init("auth");

    // The `migrate` subcommand runs the embedded migrations and exits — used by the
    // PreSync Job so the long-running server need not migrate on startup. Phase 3c:
    // once the server connects as the least-privilege iam_app it cannot run DDL.
    let migrate_only = std::env::args().nth(1).as_deref() == Some("migrate");

    if !migrate_only {
        if let Err(e) = common::config::validate_security() {
            anyhow::bail!("insecure configuration: {e}");
        }
    }

    let db_url = common::must_env("AUTH_DATABASE_URL");

    // Connect with a startup retry loop (Postgres may still be booting; the retry
    // also lets a freshly-scheduled migrate Job survive the brief window before its
    // NetworkPolicy is programmed).
    let pool = connect_with_retry(&db_url).await?;

    // Run migrations for the `migrate` subcommand, or on startup unless
    // AUTO_MIGRATE=false (set at cutover once the Job owns them and the server
    // connects as iam_app, which cannot run DDL).
    if migrate_only || common::env_or("AUTO_MIGRATE", "true") != "false" {
        sqlx::migrate!("./migrations").run(&pool).await?;
        tracing::info!("migrations applied");
    } else {
        tracing::info!("auto-migrate disabled (AUTO_MIGRATE=false) — migrations run by the Job");
    }
    if migrate_only {
        return Ok(());
    }

    let port = common::env_or("AUTH_GRPC_PORT", "50051");

    let jwt_cfg = JwtConfig::from_env();
    let jwt = keys::load_jwt_manager(&pool, jwt_cfg.issuer.clone(), jwt_cfg.access_ttl_secs).await?;

    let repo = Repo::new(pool);
    bootstrap_admin(&repo).await?;
    bootstrap_oidc_client(&repo).await?;
    bootstrap_demo(&repo).await?;

    // Outbox relay → NATS JetStream. Optional: without NATS_URL events are still
    // recorded; the gateway's lazy profile healing keeps the system working.
    match common::config::nats_url() {
        url if !url.is_empty() => {
            let js = common::events::connect(&url).await?;
            common::events::ensure_stream(&js).await?;
            let relay_repo = repo.clone();
            let saga_repo = repo.clone();
            let saga_js = js.clone();
            tokio::spawn(async move { relay::run(relay_repo, js).await });
            tracing::info!(nats = %url, "outbox relay started");
            // Saga: roll back identities whose profile creation failed permanently.
            if let Err(e) = saga::run(saga_repo, saga_js).await {
                tracing::warn!(error = %e, "saga compensator failed to start");
            }
        }
        _ => tracing::warn!("NATS_URL not set — event publishing disabled"),
    }

    // Optional Redis: shared access-token denylist + permission cache across
    // replicas; falls back to Postgres/no-cache when REDIS_URL is unset.
    let cache = cache::Cache::new(&common::env_or("REDIS_URL", "")).await;
    if cache.enabled() {
        tracing::info!("auth cache: redis-backed (shared denylist + permission cache)");
    } else {
        tracing::info!("auth cache: disabled (postgres denylist, no permission cache)");
    }
    // TS3: encrypt TOTP shared secrets at rest. Without TOTP_ENC_KEY this is a
    // passthrough (plaintext, as before) so dev/CI keep working; production sets it.
    let totp_enc = totpsecret::Encryptor::new(&common::env_or("TOTP_ENC_KEY", ""));
    if totp_enc.enabled() {
        tracing::info!("totp secrets: encrypted at rest (AES-256-GCM)");
    } else {
        tracing::warn!("totp secrets: plaintext at rest — set TOTP_ENC_KEY to encrypt");
    }
    let svc = AuthSvc::new(repo, jwt, jwt_cfg.refresh_ttl_secs, Box::new(common::email::LogSender), cache, totp_enc);

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<AuthServiceServer<AuthSvc>>().await;

    // Defense-in-depth: require the shared internal token on AuthService calls.
    // Health is left ungated so K8s/compose probes work. Fail-closed: a missing
    // token rejects every call unless INTERNAL_AUTH_OPTIONAL is explicitly set,
    // so a misconfigured deploy is locked rather than wide open.
    let token = common::config::internal_token();
    let optional = token.is_empty() && common::config::internal_auth_optional();
    let check = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        if optional {
            return Ok(req);
        }
        match req.metadata().get("x-internal-token").and_then(|v| v.to_str().ok()) {
            Some(t) if !token.is_empty() && t == token => Ok(req),
            _ => Err(tonic::Status::unauthenticated(
                "missing or invalid internal service token",
            )),
        }
    };

    let addr = format!("0.0.0.0:{port}").parse()?;
    tracing::info!(%addr, "auth service listening");
    Server::builder()
        // Trace each gRPC call and continue the caller's trace (OTLP → Jaeger).
        .layer(tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer::default())
        .add_service(health_service)
        .add_service(AuthServiceServer::with_interceptor(svc, check))
        .serve(addr)
        .await?;
    Ok(())
}

async fn connect_with_retry(url: &str) -> anyhow::Result<sqlx::PgPool> {
    let mut last_err = None;
    for _ in 0..15 {
        match PgPoolOptions::new().max_connections(10).connect(url).await {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(anyhow::anyhow!(
        "postgres not reachable: {}",
        last_err.unwrap()
    ))
}

/// Idempotently create the bootstrap admin from env credentials.
async fn bootstrap_admin(repo: &Repo) -> anyhow::Result<()> {
    let email = common::env_or("BOOTSTRAP_ADMIN_EMAIL", "");
    let pass = common::env_or("BOOTSTRAP_ADMIN_PASSWORD", "");
    if email.is_empty() || pass.is_empty() {
        return Ok(());
    }
    if repo.get_user_by_email(&email).await?.is_some() {
        return Ok(());
    }
    let hash = common::password::hash(&pass)
        .map_err(|e| anyhow::anyhow!("hash admin password: {e}"))?;
    let id = repo.create_user_with_role(&email, &hash, "admin").await?;
    // M6: the bootstrap admin is a member of the default tenant.
    let default_tenant =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    repo.create_membership(id, default_tenant).await?;
    tracing::info!(email, "bootstrap admin created");
    Ok(())
}

// Read-only demo account for the public demo so anyone can sign in and look
// around without being able to change anything. Assigned the built-in "viewer"
// role (every *:read permission, seeded by migration 0015). Idempotent.
async fn bootstrap_demo(repo: &Repo) -> anyhow::Result<()> {
    let email = common::env_or("DEMO_EMAIL", "demo@iam.local");
    let pass = common::env_or("DEMO_PASSWORD", "demo1234");
    if email.is_empty() || pass.is_empty() {
        return Ok(());
    }
    if repo.get_user_by_email(&email).await?.is_some() {
        return Ok(());
    }
    let hash = common::password::hash(&pass)
        .map_err(|e| anyhow::anyhow!("hash demo password: {e}"))?;
    let id = repo.create_user_with_role(&email, &hash, "viewer").await?;
    let default_tenant =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    repo.create_membership(id, default_tenant).await?;
    tracing::info!(email, "bootstrap demo created");
    Ok(())
}

/// Seed a demo confidential client (the admin console) on first boot. Idempotent.
async fn bootstrap_oidc_client(repo: &Repo) -> anyhow::Result<()> {
    let client_id = common::env_or("OIDC_CONSOLE_CLIENT_ID", "iam-admin-console");
    let secret = common::env_or("OIDC_CONSOLE_SECRET", "console-demo-secret-change-me");
    let redirects: Vec<String> =
        common::env_or("OIDC_CONSOLE_REDIRECT_URIS", "http://localhost:3000/api/auth/callback/iam")
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    let hash = hex::encode(Sha256::digest(secret.as_bytes()));
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, grant_types, is_confidential) \
         VALUES ($1,$2,'IAM Admin Console',$3, ARRAY['openid','profile','email'], ARRAY['authorization_code','refresh_token'], true) \
         ON CONFLICT (client_id) DO NOTHING",
    )
    .bind(&client_id)
    .bind(&hash)
    .bind(&redirects)
    .execute(&repo.pool)
    .await?;
    Ok(())
}
