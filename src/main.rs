mod grpc;
mod relay;
mod repo;

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;

use common::config::JwtConfig;
use common::jwt::JwtManager;
use proto::auth::v1::auth_service_server::AuthServiceServer;

use crate::grpc::AuthSvc;
use crate::repo::Repo;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    common::telemetry::init("auth");

    if let Err(e) = common::config::validate_security() {
        anyhow::bail!("insecure configuration: {e}");
    }

    let db_url = common::must_env("AUTH_DATABASE_URL");
    let port = common::env_or("AUTH_GRPC_PORT", "50051");

    // Connect with a startup retry loop (Postgres may still be booting).
    let pool = connect_with_retry(&db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    let repo = Repo::new(pool);
    bootstrap_admin(&repo).await?;

    // Outbox relay → NATS JetStream. Optional: without NATS_URL events are still
    // recorded; the gateway's lazy profile healing keeps the system working.
    match common::config::nats_url() {
        url if !url.is_empty() => {
            let js = common::events::connect(&url).await?;
            common::events::ensure_stream(&js).await?;
            let relay_repo = repo.clone();
            tokio::spawn(async move { relay::run(relay_repo, js).await });
            tracing::info!(nats = %url, "outbox relay started");
        }
        _ => tracing::warn!("NATS_URL not set — event publishing disabled"),
    }

    let jwt_cfg = JwtConfig::from_env();
    let jwt = JwtManager::new(&jwt_cfg);
    let svc = AuthSvc::new(repo, jwt, jwt_cfg.refresh_ttl_secs, Box::new(common::email::LogSender));

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<AuthServiceServer<AuthSvc>>().await;

    // Defense-in-depth: require the shared internal token on AuthService calls.
    // Health is left ungated so K8s/compose probes work.
    let token = common::config::internal_token();
    let check = move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
        if token.is_empty() {
            return Ok(req);
        }
        match req.metadata().get("x-internal-token").and_then(|v| v.to_str().ok()) {
            Some(t) if t == token => Ok(req),
            _ => Err(tonic::Status::unauthenticated(
                "missing or invalid internal service token",
            )),
        }
    };

    let addr = format!("0.0.0.0:{port}").parse()?;
    tracing::info!(%addr, "auth service listening");
    Server::builder()
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
    repo.create_user_with_role(&email, &hash, "admin").await?;
    tracing::info!(email, "bootstrap admin created");
    Ok(())
}
