-- Add up migration script here
CREATE TABLE IF NOT EXISTS plans (
    name TEXT PRIMARY KEY,
    max_storage_bytes BIGINT NOT NULL DEFAULT 0,
    stripe_price_id TEXT UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert a default 'free' plan if it doesn't exist
INSERT INTO plans (name, max_storage_bytes, stripe_price_id, description)
VALUES ('free', 0, NULL, 'Free tier with limited storage')
ON CONFLICT (name) DO NOTHING;

-- Optionally, insert other default plans based on common configurations
-- Users can add more at runtime via admin interfaces or direct DB access

-- Ensure existing user tiers are in the plans table
-- This assumes current tiers in users table are text and need to be migrated
INSERT INTO plans (name, max_storage_bytes)
SELECT DISTINCT tier, 0 FROM users
WHERE tier IS NOT NULL
ON CONFLICT (name) DO NOTHING;

-- Add foreign key constraint to users.tier referencing plans.name
ALTER TABLE users
ADD CONSTRAINT fk_user_tier_plan
FOREIGN KEY (tier) REFERENCES plans(name)
ON UPDATE CASCADE
ON DELETE SET NULL;
