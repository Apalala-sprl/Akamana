//! Épinglage de la clé d'hôte SSH (TOFU).
//!
//! Akamana se connecte en SSH pour déployer des certificats et pour pousser
//! des sauvegardes. Les deux connexions transportent ce que l'application a de
//! plus sensible : une clé privée de service d'un côté, la base entière de
//! l'autre. Tant que la clé d'hôte n'était pas vérifiée, n'importe quelle
//! machine capable de répondre à la place de la vraie — DNS détourné, ARP
//! empoisonné, bail DHCP hostile — recevait ces données et les identifiants
//! SSH qui vont avec.
//!
//! Le modèle retenu est celui d'OpenSSH : *trust on first use*. La première
//! connexion à un couple hôte/port enregistre la clé présentée ; les suivantes
//! doivent présenter la même, sinon la connexion est refusée **avant** que le
//! moindre identifiant ne parte. Un serveur réinstallé change de clé : il faut
//! alors retirer l'épingle, ce que `DELETE /api/v1/ssh/host-keys/:id` permet
//! (full_admin), exactement comme on édite `known_hosts`.
//!
//! La vérification se fait après l'échange de clés mais avant
//! l'authentification : `check_server_key` se contente de noter ce qu'il a vu,
//! et l'appelant tranche ensuite. C'est ce qui permet de garder le contrôle
//! sans rendre le handler de russh capable d'interroger la base.

use crate::errors::AppError;
use chrono::Utc;
use russh_keys::PublicKeyBase64;
use sqlx::MySqlPool;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Ce que l'hôte distant a présenté pendant l'échange de clés. Le handler de
/// russh y dépose sa trouvaille, l'appelant la relit.
#[derive(Clone, Default)]
pub struct SeenHostKey(Arc<Mutex<Option<HostKey>>>);

#[derive(Clone, Debug)]
pub struct HostKey {
    pub key_type: String,
    pub public_key_b64: String,
    pub fingerprint: String,
}

impl SeenHostKey {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appelé depuis `check_server_key`. Un verrou empoisonné ne doit pas faire
    /// paniquer la connexion : on laisse simplement la case vide, et la
    /// vérification échouera faute de clé vue.
    pub fn record(&self, key: &russh_keys::key::PublicKey) {
        let vu = HostKey {
            key_type: key.name().to_string(),
            public_key_b64: key.public_key_base64(),
            fingerprint: key.fingerprint(),
        };
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(vu);
        }
    }

    pub fn take(&self) -> Option<HostKey> {
        self.0.lock().ok().and_then(|mut s| s.take())
    }
}

/// Compare la clé vue à l'épingle enregistrée, ou l'enregistre si c'est la
/// première fois. `Err` = ne pas s'authentifier.
pub async fn verify(
    pool: &MySqlPool,
    host: &str,
    port: u16,
    seen: &SeenHostKey,
) -> Result<(), AppError> {
    let Some(vue) = seen.take() else {
        return Err(AppError::Internal(
            "SSH host key was never presented — refusing to authenticate".to_string(),
        ));
    };
    let now = Utc::now().naive_utc();
    let port = i32::from(port);

    let epingle: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id, public_key_b64, fingerprint FROM ssh_host_keys WHERE host = ? AND port = ?",
    )
    .bind(host)
    .bind(port)
    .fetch_optional(pool)
    .await?;

    match epingle {
        None => {
            sqlx::query(
                "INSERT INTO ssh_host_keys (id, host, port, key_type, public_key_b64, fingerprint, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(host)
            .bind(port)
            .bind(&vue.key_type)
            .bind(&vue.public_key_b64)
            .bind(&vue.fingerprint)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await?;
            tracing::info!(
                "pinned SSH host key for {host}:{port} ({} {})",
                vue.key_type,
                vue.fingerprint
            );
            Ok(())
        }
        Some((id, attendue_b64, attendue_fp)) if attendue_b64 == vue.public_key_b64 => {
            sqlx::query("UPDATE ssh_host_keys SET last_seen_at = ? WHERE id = ?")
                .bind(now)
                .bind(&id)
                .execute(pool)
                .await?;
            let _ = attendue_fp;
            Ok(())
        }
        Some((_, _, attendue_fp)) => {
            tracing::error!(
                "SSH host key mismatch for {host}:{port}: pinned {attendue_fp}, got {}",
                vue.fingerprint
            );
            Err(AppError::Validation(format!(
                "The SSH host key of {host}:{port} has changed (pinned {attendue_fp}, now {}). \
                 Nothing was sent. If the server was legitimately rebuilt, remove its pin on the \
                 Hosts page, then retry.",
                vue.fingerprint
            )))
        }
    }
}
