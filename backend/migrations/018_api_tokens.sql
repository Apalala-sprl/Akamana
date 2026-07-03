CREATE TABLE IF NOT EXISTS api_tokens (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    comment VARCHAR(512) NULL,
    token_prefix VARCHAR(20) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    scopes VARCHAR(512) NOT NULL,
    owner_user_id CHAR(36) NOT NULL,
    owner_username VARCHAR(64) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    last_used_ip VARCHAR(64) NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at DATETIME NULL,
    INDEX ix_api_tokens_prefix (token_prefix)
)
