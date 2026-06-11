-- M6.4b: flip tenant RLS from permissive-when-unset to fail-closed. A query
-- running as the restricted iam_rls role now sees ONLY rows of the tenant named
-- by app.tenant_id (plus NULL-tenant templates / system rows). The app's
-- superuser connection still bypasses RLS, so only with_tenant-wrapped paths
-- (which always set app.tenant_id) are affected — a forgotten WHERE there can no
-- longer leak. NULLIF(...,'')::uuid avoids an invalid-uuid cast when unset.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['roles','user_roles','oauth_clients','api_keys','refresh_tokens','memberships','projects','audit_events','outbox'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I USING (
        tenant_id IS NULL
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
      )$f$, t);
  END LOOP;
END $$;
