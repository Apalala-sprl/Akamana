ALTER TABLE tls_keys ADD COLUMN IF NOT EXISTS root_ca_id INT NOT NULL DEFAULT 1;
ALTER TABLE tls_keys ADD INDEX IF NOT EXISTS idx_tls_keys_root_ca (root_ca_id, cert_level, created_at);
