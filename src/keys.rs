//! Loads RS256 signing keys from the database, generating an initial keypair on
//! first boot. The active key signs new tokens; every public key is kept for
//! verification so tokens survive key rotation (and will back JWKS).

use std::collections::HashMap;

use common::jwt::{generate_rsa_keypair, JwtManager};
use sqlx::PgPool;

/// Build a `JwtManager` from the database, generating + persisting an initial
/// RS256 keypair if none exist yet.
pub async fn load_jwt_manager(
    pool: &PgPool,
    issuer: String,
    access_ttl_secs: i64,
) -> anyhow::Result<JwtManager> {
    let rows: Vec<(String, String, String, bool)> =
        sqlx::query_as("SELECT kid, private_pem, public_pem, active FROM oidc_signing_keys")
            .fetch_all(pool)
            .await?;

    let mut publics: HashMap<String, String> = HashMap::new();
    let active: (String, String); // (kid, private_pem)

    if rows.is_empty() {
        let (kid, priv_pem, pub_pem) =
            generate_rsa_keypair().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        sqlx::query(
            "INSERT INTO oidc_signing_keys (kid, private_pem, public_pem, alg, active) \
             VALUES ($1, $2, $3, 'RS256', true)",
        )
        .bind(&kid)
        .bind(&priv_pem)
        .bind(&pub_pem)
        .execute(pool)
        .await?;
        publics.insert(kid.clone(), pub_pem);
        active = (kid, priv_pem);
    } else {
        let mut found: Option<(String, String)> = None;
        for (kid, priv_pem, pub_pem, is_active) in rows {
            publics.insert(kid.clone(), pub_pem);
            if is_active {
                found = Some((kid, priv_pem));
            }
        }
        active = found.ok_or_else(|| anyhow::anyhow!("no active signing key"))?;
    }

    JwtManager::from_pem(active.0, &active.1, &publics, issuer, access_ttl_secs)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}
