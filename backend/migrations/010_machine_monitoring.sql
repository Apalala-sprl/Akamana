CREATE TABLE IF NOT EXISTS machine_monitor_ports (
    id CHAR(36) PRIMARY KEY,
    machine_id CHAR(36) NOT NULL,
    port INT NOT NULL,
    monitor_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    check_tls BOOLEAN NOT NULL DEFAULT TRUE,
    last_checked_at DATETIME NULL,
    last_status VARCHAR(32) NULL,
    last_error TEXT NULL,
    cert_not_before DATETIME NULL,
    cert_not_after DATETIME NULL,
    cert_subject TEXT NULL,
    cert_issuer TEXT NULL,
    cert_serial_hex VARCHAR(128) NULL,
    cert_chain_json JSON NULL,
    cert_diagnostic TEXT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE KEY uniq_machine_monitor_port (machine_id, port),
    CONSTRAINT fk_machine_monitor_ports_machine FOREIGN KEY (machine_id) REFERENCES machines(id)
);

CREATE INDEX IF NOT EXISTS idx_machine_monitor_due
    ON machine_monitor_ports (monitor_enabled, last_checked_at);
