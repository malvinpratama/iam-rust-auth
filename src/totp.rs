//! TOTP (RFC 6238) secret generation, code validation, and one-time recovery
//! codes for the 2FA flow. Backed by totp-rs (SHA1/6 digits/30s — the default
//! authenticator-app configuration).

use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "IAM";

pub struct GenSecret {
    pub base32: String,
    pub otpauth_uri: String,
}

/// Generate a new TOTP secret for the given account (email).
pub fn generate(account: &str) -> Option<GenSecret> {
    let secret = Secret::generate_secret();
    let bytes = secret.to_bytes().ok()?;
    let base32 = secret.to_encoded().to_string();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .ok()?;
    Some(GenSecret { base32, otpauth_uri: totp.get_url() })
}

/// Report whether `code` is a currently-valid TOTP for the base32 `secret`.
pub fn validate(code: &str, secret_b32: &str) -> bool {
    let bytes = match Secret::Encoded(secret_b32.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some(ISSUER.to_string()), "iam".to_string()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

/// Generate n random recovery codes (format xxxx-xxxx). Shown once; stored hashed.
pub fn generate_recovery_codes(n: usize) -> Vec<String> {
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789"; // no ambiguous chars
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            let s: String = (0..8).map(|_| ALPHA[rng.gen_range(0..ALPHA.len())] as char).collect();
            format!("{}-{}", &s[..4], &s[4..])
        })
        .collect()
}
