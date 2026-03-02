-- Add restricted_password_hash column to users table
-- NULL means restricted mode is disabled for this user
ALTER TABLE users ADD COLUMN restricted_password_hash TEXT;
