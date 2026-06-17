-- Phase 3c (T4) prep: reclassify the RLS tables ahead of the iam_app cutover.
--
-- Once the app connects as the non-superuser iam_app, RLS applies to EVERY query
-- (no superuser bypass). Some tables are looked up by a non-tenant key BEFORE the
-- tenant is known — a chicken-and-egg the fail-closed policy can't satisfy:
--   refresh_tokens / api_keys : looked up by an unguessable secret hash
--   oauth_clients             : looked up by client_id to DISCOVER its tenant
--   memberships               : looked up by user_id ACROSS tenants (login resolves
--                               which tenants a user belongs to)
--   audit_events / outbox     : append-only system tables; reads (relay, admin) and
--                               writes span tenants / pre-tenant (login, register)
--
-- These stay RLS-ENABLED but get a PERMISSIVE policy: their security boundary is the
-- unguessable secret hash + the app-layer WHERE filters that already exist, NOT
-- tenant RLS. The genuinely tenant-scoped business tables — roles, user_roles,
-- projects — keep the fail-closed policy from 0013, so a forgotten WHERE there still
-- cannot leak or cross-write once we run as iam_app.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['refresh_tokens','api_keys','oauth_clients','memberships','audit_events','outbox'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    -- Permissive: access is gated by the secret hash / user_id key + app-layer
    -- filters, not by app.tenant_id. WITH CHECK (true) keeps writes working too.
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
