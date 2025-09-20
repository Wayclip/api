ALTER TABLE users
ADD COLUMN last_login_at TIMESTAMPTZ,
ADD COLUMN last_login_ip TEXT;

