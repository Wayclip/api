-- Add down migration script here
-- Revert the changes by dropping the columns.
ALTER TABLE users
DROP COLUMN last_login_at,
DROP COLUMN last_login_ip;
