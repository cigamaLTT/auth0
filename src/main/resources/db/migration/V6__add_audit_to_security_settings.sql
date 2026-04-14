-- Fix for local DBs where V5 was applied without audit columns
ALTER TABLE user_security_settings 
ADD COLUMN IF NOT EXISTS created_by VARCHAR(255),
ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255);
