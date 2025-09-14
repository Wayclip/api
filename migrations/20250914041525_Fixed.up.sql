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
