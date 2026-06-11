-- M6.4: grant the multi-tenant management permissions to the built-in admin
-- role. The tenant:*/project:*/member:* permissions were seeded in 0010 but the
-- admin grant (a CROSS JOIN over all permissions) ran back in the initial RBAC
-- seed, so it never picked them up. Re-run the grant to cover any permission
-- added since.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
