-- Add up migration script here
CREATE TYPE subscription_tier AS ENUM ('free', 'paid');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id BIGINT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    avatar_url TEXT,
    tier subscription_tier NOT NULL DEFAULT 'free',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id TEXT UNIQUE,
    stripe_subscription_id TEXT UNIQUE,
    status TEXT,
    current_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Add up migration script here

ALTER TYPE subscription_tier RENAME TO subscription_tier_old;

CREATE TYPE subscription_tier AS ENUM ('free', 'tier1', 'tier2', 'tier3');

ALTER TABLE users ALTER COLUMN tier DROP DEFAULT;

ALTER TABLE users
ALTER COLUMN tier TYPE subscription_tier
USING tier::text::subscription_tier;

ALTER TABLE users ALTER COLUMN tier SET DEFAULT 'free'::subscription_tier;

DROP TYPE subscription_tier_old;

CREATE TABLE clips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    public_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_clips_user_id ON clips(user_id);
ALTER TABLE users
ADD COLUMN is_banned BOOLEAN NOT NULL DEFAULT false;
-- Add up migration script here
ALTER TABLE users
ADD COLUMN ip_address TEXT;
-- Add up migration script here
CREATE TABLE banned_ips (
    ip_address TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE report_tokens (
    token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clip_id UUID NOT NULL REFERENCES clips(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
-- Add up migration script here
ALTER TABLE users
ADD COLUMN stripe_customer_id VARCHAR(255) UNIQUE;
ALTER TABLE users DROP CONSTRAINT users_github_id_key;
ALTER TABLE users ALTER COLUMN github_id DROP NOT NULL;
ALTER TABLE users ALTER COLUMN github_id SET DEFAULT NULL;

ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE;

CREATE TYPE credential_provider AS ENUM ('github', 'google', 'discord', 'email');

CREATE TABLE user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider credential_provider NOT NULL,
    provider_id TEXT,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_id)
);

CREATE INDEX idx_user_credentials_user_id ON user_credentials(user_id);
ALTER TABLE users
ADD COLUMN two_factor_secret TEXT,
ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_recovery_codes_user_id ON user_recovery_codes(user_id);
-- Drop legacy constraint if it exists
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_github_id_key;

-- Make github_id nullable as users can sign up with other methods
ALTER TABLE users ALTER COLUMN github_id DROP NOT NULL;
ALTER TABLE users ALTER COLUMN github_id SET DEFAULT NULL;

-- Add core fields for multi-provider auth
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

-- Add fields for 2FA
ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN NOT NULL DEFAULT false;

-- Define a type for different login providers
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'credential_provider') THEN
        CREATE TYPE credential_provider AS ENUM ('github', 'google', 'discord', 'email');
    END IF;
END$$;


-- Create a table to store credentials for different providers
CREATE TABLE IF NOT EXISTS user_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider credential_provider NOT NULL,
    provider_id TEXT, -- For OAuth providers (e.g., Google sub, Discord ID)
    password_hash TEXT, -- For email provider
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_id),
    UNIQUE(user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_user_credentials_user_id ON user_credentials(user_id);


-- Create a table for email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);


-- Create a table for 2FA recovery codes
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user_id ON user_recovery_codes(user_id);
ALTER TABLE user_credentials
ADD CONSTRAINT user_credentials_user_id_provider_key UNIQUE (user_id, provider);
-- Add up migration script here
ALTER TABLE users
ADD COLUMN deleted_at TIMESTAMPTZ;
DROP TABLE IF EXISTS subscriptions;

CREATE TYPE subscription_status AS ENUM ('active', 'trialing', 'past_due', 'canceled', 'unpaid');

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT UNIQUE NOT NULL,
    stripe_price_id TEXT NOT NULL,
    status subscription_status NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    canceled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
-- Add up migration script here
CREATE TABLE password_reset_tokens (
    token UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
-- Add up migration script here
ALTER TYPE subscription_status ADD VALUE 'incomplete';
ALTER TYPE subscription_status ADD VALUE 'disputed';
-- Add a status column to track upload progress
ALTER TABLE clips
ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'completed';

-- Update existing clips to have the 'completed' status
UPDATE clips SET status = 'completed';
-- Create a new ENUM type for user roles
CREATE TYPE user_role AS ENUM ('user', 'admin');

-- Add the 'role' column to the 'users' table
ALTER TABLE users
ADD COLUMN role user_role NOT NULL DEFAULT 'user';
ALTER TABLE users
ADD COLUMN last_login_at TIMESTAMPTZ,
ADD COLUMN last_login_ip TEXT;

CREATE TABLE user_login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_login_history_user_id_created_at ON user_login_history(user_id, created_at DESC);

ALTER TABLE users
ADD COLUMN security_stamp UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE users ALTER COLUMN tier TYPE TEXT USING (tier::text);
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
ALTER TABLE plans
ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT false;

UPDATE plans SET is_default = true WHERE name = 'free';
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_session_token ON user_sessions(session_token);
