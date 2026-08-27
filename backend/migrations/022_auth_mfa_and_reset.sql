ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) NULL;

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT NULL;

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_confirmed_at DATETIME NULL;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_by VARCHAR(64) NOT NULL,
    requested_ip VARCHAR(64) NULL,
    INDEX ix_prt_user (user_id)
);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    code_hash CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    INDEX ix_urc_user (user_id)
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    name VARCHAR(128) NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    passkey_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME NULL,
    INDEX ix_wac_user (user_id)
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    state_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    success BOOLEAN NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX ix_la_username_time (username, created_at),
    INDEX ix_la_ip_time (source_ip, created_at)
);
