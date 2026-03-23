-- Drop all the data from the user secrets
-- since we're changing the metadata type
DELETE FROM user_secrets;

-- Index for efficient lookups by secret type
CREATE INDEX idx_user_secrets_type ON user_secrets (secret_type);

ALTER TABLE user_secrets RENAME COLUMN code TO id;
ALTER TABLE user_secrets RENAME COLUMN user TO user_data;
ALTER TABLE user_secrets DROP COLUMN metadata;
ALTER TABLE user_secrets ADD COLUMN secret_type TEXT NOT NULL;
ALTER TABLE user_secrets ADD COLUMN metadata TEXT NOT NULL;
