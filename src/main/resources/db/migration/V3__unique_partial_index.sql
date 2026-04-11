-- Add is_deleted column for Soft Delete support
ALTER TABLE users ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE NOT NULL;

-- Create partial indexes for unique constraints that ignore deleted users
-- Dynamically find and drop the existing unique constraint on the email column
DO $$
DECLARE
    constraint_name_record record;
BEGIN
    FOR constraint_name_record IN
        SELECT tc.constraint_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.constraint_column_usage AS ccu
          ON tc.constraint_name = ccu.constraint_name
        WHERE constraint_type = 'UNIQUE'
          AND tc.table_name = 'users'
          AND ccu.column_name = 'email'
    LOOP
        EXECUTE 'ALTER TABLE users DROP CONSTRAINT ' || quote_ident(constraint_name_record.constraint_name);
    END LOOP;
END;
$$;

CREATE UNIQUE INDEX idx_user_email_active ON users (email) WHERE is_deleted = false;
CREATE UNIQUE INDEX idx_user_username_active ON users (username) WHERE is_deleted = false AND username IS NOT NULL;

-- Create UserDevices table for Fingerprinting
CREATE TABLE user_devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id),
    device_id VARCHAR(255) NOT NULL,
    device_signature VARCHAR(512),
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_login_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    is_trusted BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_by VARCHAR(255) DEFAULT 'system' NOT NULL,
    updated_by VARCHAR(255) DEFAULT 'system' NOT NULL
);
