CREATE TABLE IF NOT EXISTS security_events (
  id CHAR(36) PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  actor VARCHAR(255) NOT NULL DEFAULT '',
  details_json TEXT NOT NULL,
  created_at DATETIME NOT NULL
);

ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_security_events_created_at (created_at);
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_security_events_type_ip (event_type, source_ip, created_at);
