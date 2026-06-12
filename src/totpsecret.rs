//! Envelope encryption for TOTP shared secrets at rest (TS3). Unlike passwords
//! or recovery codes — hashed one-way — a TOTP shared secret must be recoverable
//! to compute the rolling code, so it is encrypted with AES-256-GCM under a key
//! derived from the `TOTP_ENC_KEY` env value rather than hashed.
//!
//! Stored values are tagged `enc:v1:`. A value without that prefix is read as
//! legacy plaintext, so enabling encryption needs no data migration: existing
//! secrets keep working and re-encrypt the next time they're written (re-enroll).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

const PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12; // AES-GCM 96-bit nonce

/// Encrypts and decrypts TOTP secrets. With no key configured it is a
/// passthrough (plaintext in, plaintext out) so local/dev runs keep working;
/// production should set `TOTP_ENC_KEY`.
pub struct Encryptor {
    cipher: Option<Aes256Gcm>,
}

impl Encryptor {
    /// Build from the raw `TOTP_ENC_KEY` value. Empty = passthrough. A value that
    /// base64-decodes to exactly 32 bytes is used directly as the AES-256 key;
    /// any other non-empty value is SHA-256-derived to 32 bytes.
    pub fn new(key: &str) -> Self {
        if key.is_empty() {
            return Self { cipher: None };
        }
        let raw = derive_key(key);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw));
        Self { cipher: Some(cipher) }
    }

    /// Whether encryption is active (a key was configured).
    pub fn enabled(&self) -> bool {
        self.cipher.is_some()
    }

    /// At-rest form of a plaintext TOTP secret. Passthrough when no key is set.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        let Some(cipher) = &self.cipher else {
            return Ok(plaintext.to_string());
        };
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("encrypt totp secret: {e}"))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ct);
        Ok(format!("{PREFIX}{}", STANDARD.encode(out)))
    }

    /// Reverse of `encrypt`. A value without the `enc:v1:` prefix is legacy
    /// plaintext and is returned unchanged. An encrypted value with no key is an
    /// error rather than a silent bypass.
    pub fn decrypt(&self, stored: &str) -> Result<String, String> {
        let Some(rest) = stored.strip_prefix(PREFIX) else {
            return Ok(stored.to_string()); // legacy plaintext
        };
        let cipher = self
            .cipher
            .as_ref()
            .ok_or("totp secret is encrypted but TOTP_ENC_KEY is not set")?;
        let raw = STANDARD.decode(rest).map_err(|e| format!("decode totp secret: {e}"))?;
        if raw.len() < NONCE_LEN {
            return Err("totp secret ciphertext too short".into());
        }
        let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|e| format!("decrypt totp secret: {e}"))?;
        String::from_utf8(pt).map_err(|e| format!("totp secret not utf-8: {e}"))
    }
}

/// 32-byte AES-256 key: a base64 value of exactly 32 raw bytes is used verbatim;
/// otherwise the key material is SHA-256-derived.
fn derive_key(key: &str) -> [u8; 32] {
    if let Ok(b) = STANDARD.decode(key) {
        if b.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            return k;
        }
    }
    let digest = Sha256::digest(key.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&digest);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key32() -> String {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        STANDARD.encode(b)
    }

    #[test]
    fn round_trip() {
        let e = Encryptor::new(&key32());
        let stored = e.encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert!(stored.starts_with(PREFIX), "missing prefix: {stored}");
        assert!(!stored.contains("JBSWY3DPEHPK3PXP"), "plaintext leaked");
        assert_eq!(e.decrypt(&stored).unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn nonce_is_random() {
        let e = Encryptor::new(&key32());
        assert_ne!(e.encrypt("same").unwrap(), e.encrypt("same").unwrap());
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        let e = Encryptor::new(&key32());
        assert_eq!(e.decrypt("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn passthrough_when_no_key() {
        let e = Encryptor::new("");
        assert!(!e.enabled());
        assert_eq!(e.encrypt("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn encrypted_value_without_key_errors() {
        let stored = Encryptor::new(&key32()).encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert!(Encryptor::new("").decrypt(&stored).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let stored = Encryptor::new(&key32()).encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert!(Encryptor::new(&key32()).decrypt(&stored).is_err());
    }

    #[test]
    fn short_string_key_is_accepted() {
        let e = Encryptor::new("a-short-passphrase-not-32-bytes");
        let stored = e.encrypt("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(e.decrypt(&stored).unwrap(), "JBSWY3DPEHPK3PXP");
    }
}
