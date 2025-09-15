-- Add up migration script here
CREATE TABLE password_reset_tokens (
    token UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
