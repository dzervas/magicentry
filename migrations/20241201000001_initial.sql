-- Initial schema for magicentry SQLite database
-- Replaces reindeer/sled storage with SQLite

-- User secrets table
CREATE TABLE user_secrets (
    id TEXT PRIMARY KEY NOT NULL,
    secret_type TEXT NOT NULL,
    user_data TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    metadata TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for efficient lookups by secret type
CREATE INDEX idx_user_secrets_type ON user_secrets (secret_type);

-- Index for efficient cleanup of expired secrets
CREATE INDEX idx_user_secrets_expires_at ON user_secrets (expires_at);

-- Passkey store table
CREATE TABLE passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_data TEXT NOT NULL,
    passkey_data TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Config KV store table
CREATE TABLE config_kv (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
