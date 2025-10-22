ALTER TABLE user_secrets RENAME COLUMN id TO code ;
ALTER TABLE user_secrets RENAME COLUMN user_data TO user ;
ALTER TABLE user_secrets RENAME COLUMN secret_type TO type ;

DROP INDEX idx_user_secrets_type ;
