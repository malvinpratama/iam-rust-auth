-- Add the role:write permission (manage roles and their permissions) and grant to admin.

INSERT INTO permissions (name, description) VALUES
    ('role:write', 'Create, update, delete roles and grant/revoke their permissions')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r JOIN permissions p ON p.name = 'role:write'
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
