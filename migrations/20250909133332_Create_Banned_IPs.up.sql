-- Add up migration script here
CREATE TABLE banned_ips (
    ip_address TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
