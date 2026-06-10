-- OAuth2 / OIDC provider storage: registered clients, authorization codes
-- (Authorization Code + PKCE flow), and remembered user consents.

CREATE TABLE oauth_clients (
    client_id          TEXT        PRIMARY KEY,
    client_secret_hash TEXT,                       -- NULL for public (PKCE-only) clients
    name               TEXT        NOT NULL,
    redirect_uris      TEXT[]      NOT NULL DEFAULT '{}',
    grant_types        TEXT[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes             TEXT[]      NOT NULL DEFAULT '{openid,profile,email}',
    is_confidential    BOOLEAN     NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oauth_authorization_codes (
    code_hash             TEXT        PRIMARY KEY,  -- SHA-256 of the code, never the code itself
    client_id             TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id               UUID        NOT NULL,
    redirect_uri          TEXT        NOT NULL,
    scope                 TEXT        NOT NULL,
    code_challenge        TEXT,                     -- PKCE challenge
    code_challenge_method TEXT,                     -- 'S256' | 'plain'
    nonce                 TEXT,                     -- OIDC nonce, echoed in the id_token
    expires_at            TIMESTAMPTZ NOT NULL,
    used                  BOOLEAN     NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX oauth_authorization_codes_expires_at ON oauth_authorization_codes (expires_at);

CREATE TABLE oauth_consents (
    user_id    UUID        NOT NULL,
    client_id  TEXT        NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scopes     TEXT[]      NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
