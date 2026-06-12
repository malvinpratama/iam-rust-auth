-- A read-only "viewer" role for the public demo: every *:read permission, no
-- writes. Built-in template (tenant_id NULL) like admin/user, shared across
-- tenants. The demo user itself is created at startup (bootstrap_demo).

INSERT INTO roles (name, description, tenant_id)
SELECT 'viewer', 'Read-only access (public demo)', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM roles WHERE name = 'viewer' AND tenant_id IS NULL
);

-- Grant every read permission to viewer (user:read, role:read, tenant:read,
-- project:read, member:read, audit:read, profile:read, …).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name LIKE '%:read'
WHERE r.name = 'viewer' AND r.tenant_id IS NULL
ON CONFLICT DO NOTHING;
