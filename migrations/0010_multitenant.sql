-- M6: multi-tenant + multi-project foundation.
-- One global identity (users/profiles stay global); a user is a MEMBER of N
-- tenants with roles scoped per-tenant and per-project. RLS is rolled out
-- permissive-when-unset here (unwired services keep working) and tightened to
-- fail-closed once every path sets app.tenant_id (later phase).

-- Fixed UUIDs shared by both stacks so backfilled data lines up.
-- default tenant  = 00000000-0000-0000-0000-000000000001
-- default project = 00000000-0000-0000-0000-000000000002

-- ── 1. New tables ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);
CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);

CREATE TABLE IF NOT EXISTS memberships (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON memberships(tenant_id);

-- ── 2. Seed default tenant + project ────────────────────────
INSERT INTO tenants (id, slug, name) VALUES
    ('00000000-0000-0000-0000-000000000001', 'default', 'Default Organization')
ON CONFLICT (id) DO NOTHING;
INSERT INTO projects (id, tenant_id, slug, name) VALUES
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'default', 'Default Project')
ON CONFLICT (id) DO NOTHING;

-- ── 3. Tenant-scope columns (nullable for backfill) ─────────
ALTER TABLE roles          ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE user_roles     ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE user_roles     ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE oauth_clients  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE oauth_clients  ADD COLUMN IF NOT EXISTS default_project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE audit_events   ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE outbox         ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE api_keys       ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE api_keys       ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

-- New seeded permissions for tenant/project/member management + a platform role.
INSERT INTO permissions (name, description) VALUES
    ('tenant:read',   'Read tenant settings/members'),
    ('tenant:write',  'Create/update/delete tenants'),
    ('project:read',  'Read projects'),
    ('project:write', 'Create/update/delete projects'),
    ('member:read',   'List members'),
    ('member:write',  'Add/remove members')
ON CONFLICT (name) DO NOTHING;

-- ── 4. Backfill existing rows → default tenant ──────────────
INSERT INTO memberships (user_id, tenant_id)
SELECT id, '00000000-0000-0000-0000-000000000001' FROM users
ON CONFLICT DO NOTHING;

-- Built-in roles (admin, user) stay tenant_id NULL = shared templates; any
-- other pre-existing role belongs to the default tenant.
UPDATE roles SET tenant_id = '00000000-0000-0000-0000-000000000001'
WHERE name NOT IN ('admin', 'user') AND tenant_id IS NULL;

UPDATE user_roles     SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE oauth_clients  SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE api_keys       SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
UPDATE refresh_tokens SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
-- audit_events / outbox keep tenant_id NULL for historical/system rows.

-- ── 5. Tighten constraints ──────────────────────────────────
ALTER TABLE user_roles     ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE oauth_clients  ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE api_keys       ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN tenant_id SET NOT NULL;

-- roles: built-in names unique among templates; tenant roles unique per tenant.
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS roles_builtin_name ON roles (name) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_name  ON roles (tenant_id, name) WHERE tenant_id IS NOT NULL;

-- user_roles: assignment is unique per (user, role, tenant, project); NULL
-- project collapses to a sentinel so "tenant-wide" is a single distinct row.
ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS user_roles_unique ON user_roles
    (user_id, role_id, tenant_id, COALESCE(project_id, '00000000-0000-0000-0000-000000000000'));
CREATE INDEX IF NOT EXISTS idx_user_roles_lookup ON user_roles (user_id, tenant_id);

-- ── 6. Row-Level Security (defense in depth) ────────────────
-- The policy is permissive when app.tenant_id is unset (so paths not yet wired
-- keep working) and enforced when set; tightened to fail-closed in a later
-- phase. FORCE is required because the app role OWNS these tables (owners
-- bypass plain RLS). Rows with tenant_id NULL (built-in role templates, system
-- audit/outbox) are always visible.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['roles','user_roles','oauth_clients','api_keys','refresh_tokens','memberships','projects','audit_events','outbox'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I USING (
        current_setting('app.tenant_id', true) IS NULL
        OR current_setting('app.tenant_id', true) = ''
        OR tenant_id IS NULL
        OR tenant_id = current_setting('app.tenant_id', true)::uuid
      )$f$, t);
  END LOOP;
END $$;

-- ── 7. Non-superuser role for RLS-enforced queries ──────────
-- The app connects as a superuser (owns the tables), which bypasses RLS even
-- with FORCE. Tenant-scoped operations run inside a transaction as this
-- restricted role (SET LOCAL ROLE iam_rls) so the policy actually applies.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_rls') THEN
    CREATE ROLE iam_rls NOLOGIN;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO iam_rls;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iam_rls;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_rls;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_rls;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO iam_rls;
-- Let the connection role assume iam_rls (SET ROLE) without a password.
DO $$
BEGIN
  EXECUTE format('GRANT iam_rls TO %I', current_user);
END $$;
