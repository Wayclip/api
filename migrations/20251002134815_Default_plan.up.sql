ALTER TABLE plans
ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT false;

UPDATE plans SET is_default = true WHERE name = 'Free';
