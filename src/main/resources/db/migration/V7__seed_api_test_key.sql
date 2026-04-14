INSERT INTO client_apps (id, name, api_token, redirect_url, created_at, updated_at, created_by, updated_by)
VALUES (
    'a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6', 
    'Refactor Test Client', 
    '40190fa858e57954928e72867a109e9660290f7eb6bc98b4554998894961d5bb', 
    'http://localhost:8080/callback', 
    CURRENT_TIMESTAMP, 
    CURRENT_TIMESTAMP,
    'system',
    'system'
) ON CONFLICT (name) DO NOTHING;
