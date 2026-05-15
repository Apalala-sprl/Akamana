CREATE TABLE IF NOT EXISTS notification_events (
    id CHAR(36) PRIMARY KEY,
    cert_type VARCHAR(16) NOT NULL,
    cert_id CHAR(36) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    recipient VARCHAR(1024) NOT NULL,
    status VARCHAR(32) NOT NULL,
    payload_json JSON NOT NULL,
    sent_at DATETIME NOT NULL
);
