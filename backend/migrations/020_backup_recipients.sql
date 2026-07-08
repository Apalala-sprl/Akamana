CREATE TABLE IF NOT EXISTS backup_recipients (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    key_type VARCHAR(32) NOT NULL,
    public_key_pem MEDIUMTEXT NOT NULL,
    fingerprint_sha256 VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    INDEX ix_backup_recipients_active (is_active)
)
