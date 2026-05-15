use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddonDefinition {
    pub id: String,
    pub name: String,
    pub target: String,
    pub connection: Connection,
    pub auth: Auth,
    pub deployment: Deployment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub mode: String,
    pub host_field: String,
    pub port_field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    pub mode: String,
    pub username_field: Option<String>,
    pub password_field: Option<String>,
    pub ssh_key_field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub ssh_authorized_keys_path: Option<String>,
    pub reload_command: Option<String>,
    pub post_commands: Vec<String>,
    pub options: HashMap<String, String>,
}

pub fn load_addons(dir: &str) -> Vec<AddonDefinition> {
    let mut out = Vec::new();
    let p = Path::new(dir);
    if !p.exists() {
        return out;
    }

    let Ok(entries) = fs::read_dir(p) else {
        return out;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext != "yaml" && ext != "yml" && ext != "json" {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };

        let parsed = if ext == "json" {
            serde_json::from_str::<AddonDefinition>(&text).ok()
        } else {
            serde_yaml::from_str::<AddonDefinition>(&text).ok()
        };

        if let Some(a) = parsed {
            out.push(a);
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
