CREATE TABLE user_login_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_login_history_user_id_created_at ON user_login_history(user_id, created_at DESC);

ALTER TABLE users
ADD COLUMN security_stamp UUID NOT NULL DEFAULT gen_random_uuid();
