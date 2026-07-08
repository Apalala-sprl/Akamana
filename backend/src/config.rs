use anyhow::{anyhow, Result};
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub enum AuthMode {
    Local,
    Oidc,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_exp_minutes: i64,
    pub key_encryption_key_b64: String,
    pub root_common_name: String,
    pub root_valid_years: i64,
    pub auth_mode: AuthMode,
    pub oidc_issuer: Option<String>,
    pub oidc_audience: Option<String>,
    pub oidc_jwks_url: Option<String>,
    pub oidc_role_claim: Option<String>,
    pub bootstrap_admin_username: String,
    pub bootstrap_admin_password: String,
    pub allowed_origins: Vec<String>,
    pub trusted_proxy_ips: Vec<String>,
    pub require_mfa: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let auth_mode = match std::env::var("AUTH_MODE")
            .unwrap_or_else(|_| "local".to_string())
            .as_str()
        {
            "local" => AuthMode::Local,
            "oidc" => AuthMode::Oidc,
            _ => return Err(anyhow!("AUTH_MODE must be local or oidc")),
        };

        let bootstrap_password = std::env::var("BOOTSTRAP_ADMIN_PASSWORD")?;
        if bootstrap_password.len() < 15 {
            return Err(anyhow!(
                "BOOTSTRAP_ADMIN_PASSWORD must be at least 15 characters"
            ));
        }
        if bootstrap_password == "ChangeMeNow!" || bootstrap_password == "admin" {
            return Err(anyhow!(
                "BOOTSTRAP_ADMIN_PASSWORD must not be a default or common password"
            ));
        }

        let allowed_origins: Vec<String> = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let trusted_proxy_ips: Vec<String> = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_else(|_| "".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            database_url: std::env::var("DATABASE_URL")?,
            jwt_secret: std::env::var("JWT_SECRET")?,
            jwt_exp_minutes: std::env::var("JWT_EXP_MINUTES")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(30),
            key_encryption_key_b64: std::env::var("KEY_ENCRYPTION_KEY_B64")?,
            root_common_name: std::env::var("ROOT_COMMON_NAME")
                .unwrap_or_else(|_| "CryptoKeyMancer Root CA".to_string()),
            root_valid_years: std::env::var("ROOT_VALID_YEARS")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(10),
            auth_mode,
            oidc_issuer: std::env::var("OIDC_ISSUER").ok(),
            oidc_audience: std::env::var("OIDC_AUDIENCE").ok(),
            oidc_jwks_url: std::env::var("OIDC_JWKS_URL").ok(),
            oidc_role_claim: std::env::var("OIDC_ROLE_CLAIM").ok(),
            bootstrap_admin_username: std::env::var("BOOTSTRAP_ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            bootstrap_admin_password: bootstrap_password,
            allowed_origins,
            trusted_proxy_ips,
            require_mfa: std::env::var("REQUIRE_MFA")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        })
    }

    pub fn is_trusted_proxy(&self, ip: &str) -> bool {
        if self.trusted_proxy_ips.is_empty() {
            return false;
        }
        let Ok(target_ip) = ip.parse::<IpAddr>() else {
            return false;
        };
        for proxy in &self.trusted_proxy_ips {
            if let Ok(proxy_ip) = proxy.parse::<IpAddr>() {
                if proxy_ip == target_ip {
                    return true;
                }
            }
        }
        false
    }

    pub fn resolved_client_ip(&self, forwarded_for: Option<&str>, direct_ip: &str) -> String {
        if let Some(xff) = forwarded_for {
            if self.is_trusted_proxy(direct_ip) {
                let first_ip = xff.split(',').next().map(|s| s.trim()).unwrap_or(direct_ip);
                return first_ip.to_string();
            }
        }
        direct_ip.to_string()
    }
}
