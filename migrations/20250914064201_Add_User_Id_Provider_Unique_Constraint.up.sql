ALTER TABLE user_credentials
ADD CONSTRAINT user_credentials_user_id_provider_key UNIQUE (user_id, provider);
