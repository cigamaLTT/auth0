-- Add Auditor fields to existing tables
ALTER TABLE users ADD COLUMN created_by VARCHAR(255) DEFAULT 'system' NOT NULL;
ALTER TABLE users ADD COLUMN updated_by VARCHAR(255) DEFAULT 'system' NOT NULL;
ALTER TABLE users ALTER COLUMN updated_at SET NOT NULL;

ALTER TABLE client_apps ADD COLUMN created_by VARCHAR(255) DEFAULT 'system' NOT NULL;
ALTER TABLE client_apps ADD COLUMN updated_by VARCHAR(255) DEFAULT 'system' NOT NULL;

ALTER TABLE refresh_tokens ADD COLUMN created_by VARCHAR(255) DEFAULT 'system' NOT NULL;
ALTER TABLE refresh_tokens ADD COLUMN updated_by VARCHAR(255) DEFAULT 'system' NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN updated_at SET NOT NULL;
