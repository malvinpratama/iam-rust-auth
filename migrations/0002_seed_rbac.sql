-- Seed baseline roles and permissions for RBAC.

INSERT INTO roles (name, description) VALUES
    ('admin', 'Full administrative access'),
    ('user',  'Standard authenticated user')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    ('user:read',     'Read any user'),
    ('user:write',    'Modify any user'),
    ('user:delete',   'Delete any user'),
    ('role:read',     'List roles and permissions'),
    ('role:assign',   'Assign roles to users'),
    ('profile:read',  'Read own profile'),
    ('profile:write', 'Modify own profile')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- user → profile:read, profile:write only (NOT user:read — admin-only).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r JOIN permissions p ON p.name IN ('profile:read', 'profile:write')
WHERE r.name = 'user'
ON CONFLICT DO NOTHING;
