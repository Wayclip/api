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
