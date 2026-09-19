CREATE TABLE IF NOT EXISTS tls_key_machines (
    tls_key_id CHAR(36) NOT NULL,
    machine_id CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (tls_key_id, machine_id),
    KEY idx_tkm_machine (machine_id)
);
INSERT IGNORE INTO tls_key_machines (tls_key_id, machine_id, created_at)
    SELECT id, machine_id, created_at FROM tls_keys WHERE machine_id IS NOT NULL;
