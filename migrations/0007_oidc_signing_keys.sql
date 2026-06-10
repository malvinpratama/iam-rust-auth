-- RS256 signing keys for access + ID tokens (OIDC). The auth service generates
-- an initial keypair on first boot and can rotate by inserting a new active key;
-- old public keys stay available (JWKS) until their tokens expire.
CREATE TABLE oidc_signing_keys (
    kid         TEXT        PRIMARY KEY,
    private_pem TEXT        NOT NULL,
    public_pem  TEXT        NOT NULL,
    alg         TEXT        NOT NULL DEFAULT 'RS256',
    active      BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one active signing key at a time.
CREATE UNIQUE INDEX oidc_signing_keys_one_active ON oidc_signing_keys (active) WHERE active;
