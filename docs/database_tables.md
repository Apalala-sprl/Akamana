# EZKey Database Tables

## users
- `id CHAR(36)` primary key
- `username VARCHAR(64)` unique login
- `password_hash VARCHAR(255)` Argon2 hash
- `role VARCHAR(32)` role: `full_admin`, `ssh_admin`, `tls_admin`, `auditor`, legacy `admin/operator`
- `created_at DATETIME`
- `updated_at DATETIME`

## machines
- `id CHAR(36)` primary key
- `hostname VARCHAR(255)`
- `ip_address VARCHAR(45)`
- `owner VARCHAR(255)`
- `environment VARCHAR(64)`
- `created_at DATETIME`
- `updated_at DATETIME`

## root_ca
- `id INT` fixed `1`
- `common_name VARCHAR(255)`
- `cert_pem TEXT`
- `private_key_enc MEDIUMTEXT`
- `not_before DATETIME`
- `not_after DATETIME`
- `created_at DATETIME`

## tls_keys
- existing fields +
- `root_ca_id INT` links certificate to root CA organization
- `cert_level VARCHAR(32)` (`root`, `intermediate`, `leaf`)
- `parent_cert_id CHAR(36)` nullable parent for hierarchy
- `cipher VARCHAR(64)`
- `key_length INT`
- `usages_json JSON`

## ssh_keys
- existing fields +
- `ssh_username VARCHAR(128)`
- `machine_name VARCHAR(255)`
- `cipher VARCHAR(64)`
- `key_length INT`

## crl_entries
- revoked TLS serial list

## audit_logs
- action logs (who did what, when, on what)

## access_logs
- `id CHAR(36)`
- `actor VARCHAR(64)`
- `source_ip VARCHAR(128)`
- `method VARCHAR(16)`
- `path VARCHAR(512)`
- `status_code INT`
- `details_json JSON`
- `created_at DATETIME`

## settings
- `key_name VARCHAR(128)` PK
- `value_text TEXT`
- `updated_by VARCHAR(64)`
- `updated_at DATETIME`

## user_profiles
- `user_id CHAR(36)` PK/FK users
- `picture_data_url MEDIUMTEXT`
- `updated_at DATETIME`

## notification_events
- webhook notification delivery status for expiration alerts

## security_events
- `id CHAR(36)` PK
- `event_type VARCHAR(64)` (`bruteforce_login`, `auth_attack`, ...)
- `severity VARCHAR(16)` (`high`, `medium`, `low`)
- `source_ip VARCHAR(64)`
- `actor VARCHAR(255)`
- `details_json TEXT`
- `created_at DATETIME`
