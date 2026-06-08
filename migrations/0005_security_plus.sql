-- v0.2 Security+: email verification, password reset, account lockout, audit log.
-- All additive; existing behavior is unchanged unless the related feature is enabled.

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS email_verifications (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications(user_id);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    TEXT NOT NULL DEFAULT '',
    actor_email TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);

-- New permission to read the audit log; granted to admin.
INSERT INTO permissions (name, description) VALUES
    ('audit:read', 'Read the audit log')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name = 'audit:read'
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
