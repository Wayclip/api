-- Add up migration script here
ALTER TABLE users
ADD COLUMN stripe_customer_id VARCHAR(255) UNIQUE;
