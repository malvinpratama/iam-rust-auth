-- Access-token denylist (by JWT id). Checked on ValidateToken; written on logout.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);
