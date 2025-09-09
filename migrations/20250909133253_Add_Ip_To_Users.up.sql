-- Add up migration script here
ALTER TABLE users
ADD COLUMN ip_address TEXT;
