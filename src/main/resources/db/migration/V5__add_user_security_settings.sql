-- Create user_security_settings table
CREATE TABLE user_security_settings (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE,
    require_otp_for_password BOOLEAN NOT NULL DEFAULT FALSE,
    require_otp_for_email BOOLEAN NOT NULL DEFAULT FALSE,
    require_otp_for_phone BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_user_security_settings_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Initialize settings for existing users
INSERT INTO user_security_settings (id, user_id, require_otp_for_password, require_otp_for_email, require_otp_for_phone)
SELECT gen_random_uuid(), user_id, FALSE, FALSE, FALSE FROM users;
