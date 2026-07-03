use crate::{config::Config, errors::AppError};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chrono::Utc;
use rand_core::OsRng;
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};
use uuid::Uuid;

pub async fn connect(cfg: &Config) -> Result<MySqlPool, AppError> {
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &MySqlPool) -> Result<(), AppError> {
    let migrations = [
        include_str!("../migrations/001_init.sql"),
        include_str!("../migrations/002_uix_security.sql"),
        include_str!("../migrations/003_notifications.sql"),
        include_str!("../migrations/004_root_and_publish_controls.sql"),
        include_str!("../migrations/005_siem_security.sql"),
        include_str!("../migrations/006_tls_root_scope.sql"),
        include_str!("../migrations/007_root_revocation.sql"),
        include_str!("../migrations/008_certificate_machine_optional.sql"),
        include_str!("../migrations/009_root_crypto_params.sql"),
        include_str!("../migrations/010_machine_monitoring.sql"),
        include_str!("../migrations/011_inventory_and_deployment.sql"),
        include_str!("../migrations/012_certbot_and_monitor_only.sql"),
        include_str!("../migrations/013_machine_os_type.sql"),
        include_str!("../migrations/014_root_subject_dn.sql"),
        include_str!("../migrations/015_monitor_vhost.sql"),
        include_str!("../migrations/016_monitor_tls_support.sql"),
        include_str!("../migrations/017_tls_san_eku.sql"),
        include_str!("../migrations/018_api_tokens.sql"),
        include_str!("../migrations/019_ssh_certificates.sql"),
    ];

    for migration_sql in migrations {
        for statement in migration_sql.split(';') {
            let trimmed = statement.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed).execute(pool).await?;
        }
    }
    Ok(())
}

pub async fn bootstrap_admin(pool: &MySqlPool, cfg: &Config) -> Result<(), AppError> {
    let existing: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&cfg.bootstrap_admin_username)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Ok(());
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(cfg.bootstrap_admin_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("unable to hash admin password: {e}")))?
        .to_string();

    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, 'full_admin', ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&cfg.bootstrap_admin_username)
    .bind(hash)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

struct BuiltinApp {
    slug: &'static str,
    name: &'static str,
    cert_path: &'static str,
    key_path: &'static str,
    chain_path: Option<&'static str>,
    config_dir: Option<&'static str>,
    reload_command: Option<&'static str>,
    config_example: &'static str,
}

const BUILTIN_APPS: &[BuiltinApp] = &[
    BuiltinApp {
        slug: "nginx",
        name: "Nginx",
        cert_path: "/etc/ssl/certs/service-fullchain.crt",
        key_path: "/etc/ssl/private/service.key",
        chain_path: Some("/etc/ssl/certs/service-fullchain.crt"),
        config_dir: Some("/etc/nginx/conf.d"),
        reload_command: Some("nginx -t && systemctl reload nginx"),
        config_example: "server {\n    listen 443 ssl;\n    server_name service.example.com;\n    ssl_certificate     /etc/ssl/certs/service-fullchain.crt;\n    ssl_certificate_key /etc/ssl/private/service.key;\n}",
    },
    BuiltinApp {
        slug: "apache",
        name: "Apache HTTPD",
        cert_path: "/etc/ssl/certs/service.crt",
        key_path: "/etc/ssl/private/service.key",
        chain_path: Some("/etc/ssl/certs/service-chain.crt"),
        config_dir: Some("/etc/apache2/sites-available"),
        reload_command: Some("apachectl configtest && systemctl reload apache2"),
        config_example: "<VirtualHost *:443>\n    ServerName service.example.com\n    SSLEngine on\n    SSLCertificateFile      /etc/ssl/certs/service.crt\n    SSLCertificateKeyFile   /etc/ssl/private/service.key\n    SSLCertificateChainFile /etc/ssl/certs/service-chain.crt\n</VirtualHost>",
    },
    BuiltinApp {
        slug: "traefik",
        name: "Traefik",
        cert_path: "/etc/traefik/certs/service.crt",
        key_path: "/etc/traefik/certs/service.key",
        chain_path: None,
        config_dir: Some("/etc/traefik/dynamic"),
        reload_command: None,
        config_example: "tls:\n  certificates:\n    - certFile: /etc/traefik/certs/service.crt\n      keyFile: /etc/traefik/certs/service.key",
    },
    BuiltinApp {
        slug: "haproxy",
        name: "HAProxy",
        cert_path: "/etc/haproxy/certs/service.pem",
        key_path: "/etc/haproxy/certs/service.pem",
        chain_path: None,
        config_dir: Some("/etc/haproxy"),
        reload_command: Some("haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy"),
        config_example: "frontend https-in\n    bind *:443 ssl crt /etc/haproxy/certs/service.pem\n    default_backend app",
    },
    BuiltinApp {
        slug: "ssh",
        name: "OpenSSH (authorized_keys)",
        cert_path: "~/.ssh/authorized_keys",
        key_path: "~/.ssh/authorized_keys",
        chain_path: None,
        config_dir: Some("~/.ssh"),
        reload_command: None,
        config_example: "# Append the generated public key to the user's authorized_keys:\n# ssh-ed25519 AAAA... ops-user",
    },
    BuiltinApp {
        slug: "iis",
        name: "IIS (Windows)",
        cert_path: "C:\\certs\\service.pfx",
        key_path: "C:\\certs\\service.pfx",
        chain_path: None,
        config_dir: Some("C:\\certs"),
        reload_command: None,
        config_example: "Import-PfxCertificate -FilePath C:\\certs\\service.pfx -CertStoreLocation Cert:\\LocalMachine\\My",
    },
    BuiltinApp {
        slug: "kubernetes",
        name: "Kubernetes Ingress",
        cert_path: "tls.crt",
        key_path: "tls.key",
        chain_path: None,
        config_dir: None,
        reload_command: None,
        config_example: "kubectl create secret tls service-tls --cert=tls.crt --key=tls.key -n default",
    },
];

pub async fn seed_applications(pool: &MySqlPool) -> Result<(), AppError> {
    let now = Utc::now().naive_utc();
    for app in BUILTIN_APPS {
        sqlx::query(
            "INSERT IGNORE INTO applications \
             (id, slug, name, default_cert_path, default_key_path, default_chain_path, default_config_dir, default_reload_command, config_example, is_builtin, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(app.slug)
        .bind(app.name)
        .bind(app.cert_path)
        .bind(app.key_path)
        .bind(app.chain_path)
        .bind(app.config_dir)
        .bind(app.reload_command)
        .bind(app.config_example)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
    }
    Ok(())
}
