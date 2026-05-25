CREATE TABLE IF NOT EXISTS applications (
    id CHAR(36) PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    default_cert_path VARCHAR(512) NULL,
    default_key_path VARCHAR(512) NULL,
    default_chain_path VARCHAR(512) NULL,
    default_config_dir VARCHAR(512) NULL,
    default_reload_command VARCHAR(512) NULL,
    config_example MEDIUMTEXT NULL,
    notes TEXT NULL,
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id CHAR(36) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    username VARCHAR(255) NULL,
    secret_enc MEDIUMTEXT NULL,
    ssh_private_key_enc MEDIUMTEXT NULL,
    ssh_passphrase_enc MEDIUMTEXT NULL,
    notes TEXT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS host_credentials (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    credential_id CHAR(36) NOT NULL,
    protocol VARCHAR(32) NOT NULL DEFAULT 'ssh',
    port INT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    last_check_status VARCHAR(32) NULL,
    last_check_at DATETIME NULL,
    last_check_message TEXT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uniq_host_credential (machine_id, credential_id, protocol),
    CONSTRAINT fk_host_cred_machine FOREIGN KEY (machine_id) REFERENCES machines(id),
    CONSTRAINT fk_host_cred_credential FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

CREATE TABLE IF NOT EXISTS host_applications (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    application_id CHAR(36) NOT NULL,
    tls_key_id CHAR(36) NULL,
    cert_path VARCHAR(512) NULL,
    key_path VARCHAR(512) NULL,
    chain_path VARCHAR(512) NULL,
    reload_command VARCHAR(512) NULL,
    credential_id CHAR(36) NULL,
    auto_deploy BOOLEAN NOT NULL DEFAULT FALSE,
    last_deploy_status VARCHAR(32) NULL,
    last_deploy_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT fk_host_app_machine FOREIGN KEY (machine_id) REFERENCES machines(id),
    CONSTRAINT fk_host_app_application FOREIGN KEY (application_id) REFERENCES applications(id)
);

CREATE TABLE IF NOT EXISTS deployment_jobs (
    id CHAR(36) PRIMARY KEY,
    host_application_id CHAR(36) NOT NULL,
    tls_key_id CHAR(36) NULL,
    trigger_source VARCHAR(32) NOT NULL DEFAULT 'manual',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    started_at DATETIME NULL,
    finished_at DATETIME NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    CONSTRAINT fk_depjob_host_app FOREIGN KEY (host_application_id) REFERENCES host_applications(id)
);

CREATE TABLE IF NOT EXISTS deployment_journal (
    id CHAR(36) PRIMARY KEY,
    job_id CHAR(36) NOT NULL,
    step VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL,
    message TEXT NULL,
    created_at DATETIME NOT NULL,
    KEY idx_deployment_journal_job (job_id, created_at),
    CONSTRAINT fk_journal_job FOREIGN KEY (job_id) REFERENCES deployment_jobs(id)
);

ALTER TABLE tls_keys ADD COLUMN IF NOT EXISTS auto_renew BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE tls_keys ADD COLUMN IF NOT EXISTS renew_days_before INT NOT NULL DEFAULT 30;

ALTER TABLE tls_keys ADD COLUMN IF NOT EXISTS last_status VARCHAR(32) NULL;

ALTER TABLE tls_keys ADD COLUMN IF NOT EXISTS last_status_at DATETIME NULL;

ALTER TABLE machines ADD COLUMN IF NOT EXISTS alert_email VARCHAR(255) NULL;

ALTER TABLE machines ADD COLUMN IF NOT EXISTS test_url VARCHAR(512) NULL;
