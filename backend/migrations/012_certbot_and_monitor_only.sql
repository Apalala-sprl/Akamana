ALTER TABLE machines ADD COLUMN IF NOT EXISTS monitor_only BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE deployment_jobs MODIFY host_application_id CHAR(36) NULL;

ALTER TABLE deployment_jobs ADD COLUMN IF NOT EXISTS certbot_config_id CHAR(36) NULL;

ALTER TABLE deployment_jobs ADD COLUMN IF NOT EXISTS job_type VARCHAR(32) NOT NULL DEFAULT 'deploy';

CREATE TABLE IF NOT EXISTS certbot_configs (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    credential_id CHAR(36) NULL,
    domains VARCHAR(1024) NOT NULL,
    email VARCHAR(255) NULL,
    challenge VARCHAR(32) NOT NULL DEFAULT 'webroot',
    webroot_path VARCHAR(512) NULL,
    dns_plugin VARCHAR(64) NULL,
    extra_args VARCHAR(1024) NULL,
    staging BOOLEAN NOT NULL DEFAULT FALSE,
    live_cert_path VARCHAR(512) NULL,
    live_key_path VARCHAR(512) NULL,
    last_run_status VARCHAR(32) NULL,
    last_run_at DATETIME NULL,
    last_not_after DATETIME NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    renew_days_before INT NOT NULL DEFAULT 30,
    created_by VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT fk_certbot_machine FOREIGN KEY (machine_id) REFERENCES machines(id),
    CONSTRAINT fk_certbot_credential FOREIGN KEY (credential_id) REFERENCES credentials(id)
);
