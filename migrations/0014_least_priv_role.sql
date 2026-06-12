-- Phase 3c (T4): prepare a least-privilege runtime role, `iam_app`, for the
-- application to connect as INSTEAD of the superuser `app`.
--
-- WHY: a Postgres superuser BYPASSES Row-Level Security even with FORCE, so today
-- the tenant_isolation policy only bites inside the iam_rls transactions that
-- with_tenant opens (Phase 3b). A non-superuser connection role makes RLS apply
-- to EVERY query by default — real defense in depth.
--
-- This migration only PREPARES the role. It is created NOLOGIN so nothing can
-- connect as it yet; the operator enables login + sets a password at cutover.
-- Cutover is intentionally STAGED — see the least-privilege-db runbook. The
-- fail-closed policy returns zero rows / rejects writes when app.tenant_id is
-- unset, so the app may only connect as iam_app once EVERY access to an
-- RLS-enabled table sets a tenant context. Phase 3b covers the tenant-admin
-- writes; login / register / refresh / validate / api-key paths must follow
-- before DATABASE_URL points at iam_app.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_app') THEN
    CREATE ROLE iam_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO iam_app', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO iam_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iam_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO iam_app;

-- iam_app must be able to assume iam_rls (the role with_tenant elevates to).
-- NOINHERIT keeps it explicit: iam_app only gains those rights via SET ROLE.
GRANT iam_rls TO iam_app;
