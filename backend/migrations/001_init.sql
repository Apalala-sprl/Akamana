CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS machines (
    id CHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    environment VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uniq_machine_host_ip (hostname, ip_address)
);

CREATE TABLE IF NOT EXISTS root_ca (
    id INT PRIMARY KEY,
    common_name VARCHAR(255) NOT NULL,
    cert_pem TEXT NOT NULL,
    private_key_enc MEDIUMTEXT NOT NULL,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS tls_keys (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    serial_hex VARCHAR(64) NOT NULL UNIQUE,
    cert_pem TEXT NOT NULL,
    private_key_enc MEDIUMTEXT NOT NULL,
    valid_from DATETIME NOT NULL,
    valid_to DATETIME NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at DATETIME NULL,
    revoked_reason VARCHAR(255) NULL,
    CONSTRAINT fk_tls_machine FOREIGN KEY (machine_id) REFERENCES machines(id)
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    public_key TEXT NOT NULL,
    private_key_enc MEDIUMTEXT NOT NULL,
    fingerprint_sha256 VARCHAR(255) NOT NULL,
    valid_from DATETIME NOT NULL,
    valid_to DATETIME NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at DATETIME NULL,
    revoked_reason VARCHAR(255) NULL,
    CONSTRAINT fk_ssh_machine FOREIGN KEY (machine_id) REFERENCES machines(id)
);

CREATE TABLE IF NOT EXISTS crl_entries (
    id CHAR(36) PRIMARY KEY,
    tls_key_id CHAR(36) NOT NULL,
    serial_hex VARCHAR(64) NOT NULL,
    revoked_at DATETIME NOT NULL,
    reason VARCHAR(255) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    CONSTRAINT fk_crl_tls_key FOREIGN KEY (tls_key_id) REFERENCES tls_keys(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id CHAR(36) PRIMARY KEY,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    details_json JSON NOT NULL,
    created_at DATETIME NOT NULL
);
