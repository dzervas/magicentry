-- Drop all the data from the user secrets
-- since we're changing the metadata type
DELETE FROM user_secrets;

DROP INDEX idx_user_secrets_type;

ALTER TABLE user_secrets RENAME COLUMN id TO code ;
ALTER TABLE user_secrets RENAME COLUMN user_data TO user ;
ALTER TABLE user_secrets DROP COLUMN secret_type ;
ALTER TABLE user_secrets DROP COLUMN metadata ;
ALTER TABLE user_secrets ADD COLUMN metadata TEXT ;
