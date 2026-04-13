-- V4__add_device_info_to_refresh_tokens.sql
-- Adds device-specific information to the refresh_tokens table to support session management.

ALTER TABLE refresh_tokens
    ADD COLUMN device_id   UUID,
    ADD COLUMN device_name VARCHAR(255),
    ADD COLUMN ip_address  VARCHAR(45),
    ADD COLUMN user_agent  TEXT,
    ADD COLUMN last_used_at TIMESTAMP WITHOUT TIME ZONE;

-- Create indexes for efficient session lookup and deletion by user
CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
