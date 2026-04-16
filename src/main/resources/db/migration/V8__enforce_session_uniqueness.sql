-- V8__enforce_session_uniqueness.sql
-- This migration ensures that each user-device pair can only have one active session at a time.

-- 1. Identify and revoke any existing duplicate active sessions (keeping only the most recent)
UPDATE refresh_tokens
SET is_revoked = true,
    updated_at = NOW(),
    updated_by = 'migration_v8'
WHERE id IN (
    SELECT id
    FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY user_id, device_id
                   ORDER BY created_at DESC
               ) as row_num
        FROM refresh_tokens
        WHERE is_revoked = false
          AND device_id IS NOT NULL
    ) t
    WHERE t.row_num > 1
);

-- 2. Create a Partial Unique Index to enforce session uniqueness for active tokens
-- This index ignores revoked tokens, allowing historical records while ensuring only one active session.
CREATE UNIQUE INDEX idx_unique_active_session 
ON refresh_tokens (user_id, device_id) 
WHERE is_revoked = false AND device_id IS NOT NULL;
