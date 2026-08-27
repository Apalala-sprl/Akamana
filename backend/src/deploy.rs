use crate::{crypto::decrypt_secret, errors::AppError, AppState};
use chrono::Utc;
use russh::client;
use russh::ChannelMsg;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct DeployTargetRow {
    hostname: String,
    ip_address: String,
    cert_path: Option<String>,
    key_path: Option<String>,
    chain_path: Option<String>,
    reload_command: Option<String>,
    default_cert_path: Option<String>,
    default_key_path: Option<String>,
    default_chain_path: Option<String>,
    default_reload_command: Option<String>,
    tls_key_id: Option<String>,
    // resolved push credential (host_application.credential_id or host default)
    cred_kind: Option<String>,
    cred_username: Option<String>,
    cred_secret_enc: Option<String>,
    cred_ssh_private_key_enc: Option<String>,
    cred_ssh_passphrase_enc: Option<String>,
    ssh_port: Option<i32>,
    // Élévation de privilèges : NULL sur la cible = hériter de l'application,
    // même convention que les chemins ci-dessus.
    use_sudo: Option<bool>,
    staging_dir: Option<String>,
    default_use_sudo: bool,
    default_staging_dir: Option<String>,
}

struct ResolvedTarget {
    cert_path: String,
    key_path: String,
    chain_path: Option<String>,
    reload_command: Option<String>,
    cert_pem: String,
    chain_pem: Option<String>,
    key_pem: String,
    host: String,
    port: u16,
    username: String,
    auth: SshAuth,
    escalation: Escalation,
}

/// Comment les fichiers atteignent un répertoire que l'utilisateur SSH ne peut
/// pas écrire, et comment la commande de rechargement obtient ses droits.
///
/// `Direct` est le comportement historique : l'utilisateur SSH écrit lui-même
/// dans le répertoire de destination et lance le rechargement sous son propre
/// compte. Il suppose un compte de déploiement propriétaire de /etc/nginx/certs
/// et autorisé à recharger le service — ce qui est rarement le cas.
///
/// `Sudo` couvre le cas courant : le compte de déploiement n'a aucun droit sur
/// le répertoire cible. Le fichier est alors déposé dans un répertoire de
/// transit appartenant à l'utilisateur, puis `sudo install` le pose à
/// destination avec le bon propriétaire et le bon mode, et le transit est
/// effacé. La commande de rechargement passe entière par `sudo -n sh -c`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Escalation {
    Direct,
    Sudo { staging_dir: String },
}

/// Répertoire de transit par défaut. Relatif : une session SSH démarre dans le
/// répertoire personnel de l'utilisateur, ce qui évite d'avoir à faire
/// développer un `~` par le shell distant — un tilde entre quotes reste un
/// tilde.
const DEFAULT_STAGING_DIR: &str = ".akamana-staging";

enum SshAuth {
    Key {
        private_key_pem: String,
        passphrase: Option<String>,
    },
    Password(String),
}

pub struct DeployResult {
    pub job_id: String,
    pub status: String,
}

pub async fn run_deployment(
    state: &AppState,
    host_application_id: &str,
    trigger: &str,
    actor: &str,
    check_only: bool,
) -> Result<DeployResult, AppError> {
    let job_type = if check_only { "check" } else { "deploy" };
    let job_id = start_job(state, host_application_id, trigger, job_type, actor).await?;

    let result = run_deployment_inner(state, host_application_id, &job_id, check_only).await;

    match &result {
        Ok(()) => {
            finish_job(state, &job_id, "success").await?;
            if !check_only {
                update_host_app_status(state, host_application_id, "success").await?;
            }
            Ok(DeployResult {
                job_id,
                status: "success".to_string(),
            })
        }
        Err(e) => {
            journal(state, &job_id, "error", "failed", &e.to_string()).await?;
            finish_job(state, &job_id, "failed").await?;
            if !check_only {
                update_host_app_status(state, host_application_id, "failed").await?;
            }
            send_failure_alert(state, host_application_id, &e.to_string()).await;
            Ok(DeployResult {
                job_id,
                status: "failed".to_string(),
            })
        }
    }
}

async fn run_deployment_inner(
    state: &AppState,
    host_application_id: &str,
    job_id: &str,
    check_only: bool,
) -> Result<(), AppError> {
    journal(
        state,
        job_id,
        "resolve",
        "running",
        "Resolving deployment target",
    )
    .await?;
    let target = resolve_target(state, host_application_id).await?;
    journal(
        state,
        job_id,
        "resolve",
        "ok",
        &format!(
            "Target {}:{} cert={} key={}",
            target.host, target.port, target.cert_path, target.key_path
        ),
    )
    .await?;

    journal(
        state,
        job_id,
        "connect",
        "running",
        "Opening SSH connection",
    )
    .await?;
    let handle = connect(&target.host, target.port, &target.username, &target.auth).await?;
    journal(state, job_id, "connect", "ok", "Authenticated over SSH").await?;

    // Pre-flight sudo : vérifier que l'élévation fonctionne sans mot de passe
    // AVANT d'écrire quoi que ce soit. Un sudoers exigeant un mot de passe est
    // le piège classique — il faut le dire ici, franchement, plutôt que de
    // laisser la première installation échouer à moitié.
    if let Escalation::Sudo { staging_dir } = &target.escalation {
        journal(
            state,
            job_id,
            "check_sudo",
            "running",
            "Checking passwordless sudo and staging directory",
        )
        .await?;
        let (code, out) = exec_command(
            &handle,
            "sudo -n true && command -v install >/dev/null && echo OK",
        )
        .await?;
        if code != 0 || !out.contains("OK") {
            return Err(AppError::Internal(format!(
                "user {} cannot run sudo without a password on {}, or coreutils `install` is missing: {}",
                target.username,
                target.host,
                out.trim()
            )));
        }
        let quoted = shell_quote(staging_dir);
        let (code, out) = exec_command(
            &handle,
            &format!(
                "mkdir -p {0} && chmod 700 {0} && test -w {0} && echo OK",
                quoted
            ),
        )
        .await?;
        if code != 0 || !out.contains("OK") {
            return Err(AppError::Internal(format!(
                "staging directory {staging_dir} could not be created or written to: {}",
                out.trim()
            )));
        }
        journal(
            state,
            job_id,
            "check_sudo",
            "ok",
            &format!("sudo available, staging in {staging_dir}"),
        )
        .await?;
    }

    // Pre-flight: verify the directories that will receive files are usable.
    // Sans sudo, il faut que l'utilisateur SSH puisse écrire lui-même ; avec
    // sudo, il suffit que le répertoire existe — c'est root qui y écrira.
    for path in [
        Some(&target.cert_path),
        Some(&target.key_path),
        target.chain_path.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let dir = parent_dir(path);
        journal(
            state,
            job_id,
            "check_writable",
            "running",
            &format!("Checking destination: {dir}"),
        )
        .await?;
        let probe = match &target.escalation {
            Escalation::Direct => {
                format!("test -d {0} && test -w {0} && echo OK", shell_quote(&dir))
            }
            Escalation::Sudo { .. } => {
                format!("sudo -n test -d {0} && echo OK", shell_quote(&dir))
            }
        };
        let (code, out) = exec_command(&handle, &probe).await?;
        if code != 0 || !out.contains("OK") {
            return Err(match &target.escalation {
                Escalation::Direct => AppError::Internal(format!(
                    "directory {dir} is missing or not writable for the deployment user"
                )),
                Escalation::Sudo { .. } => {
                    AppError::Internal(format!("directory {dir} does not exist on the host"))
                }
            });
        }
        journal(
            state,
            job_id,
            "check_writable",
            "ok",
            &format!("Destination usable: {dir}"),
        )
        .await?;
    }

    if check_only {
        journal(
            state,
            job_id,
            "check",
            "ok",
            "Pre-flight checks passed; no files written",
        )
        .await?;
        return Ok(());
    }

    write_remote_file(
        state,
        job_id,
        &handle,
        &target.escalation,
        &target.key_path,
        target.key_pem.as_bytes(),
        "600",
        "private key",
    )
    .await?;
    write_remote_file(
        state,
        job_id,
        &handle,
        &target.escalation,
        &target.cert_path,
        target.cert_pem.as_bytes(),
        "644",
        "certificate",
    )
    .await?;
    if let (Some(chain_path), Some(chain_pem)) = (&target.chain_path, &target.chain_pem) {
        write_remote_file(
            state,
            job_id,
            &handle,
            &target.escalation,
            chain_path,
            chain_pem.as_bytes(),
            "644",
            "chain",
        )
        .await?;
    }

    if let Some(reload) = &target.reload_command {
        if !reload.trim().is_empty() {
            journal(
                state,
                job_id,
                "reload",
                "running",
                &format!("Running: {reload}"),
            )
            .await?;
            let (code, out) =
                exec_command(&handle, &privileged_command(&target.escalation, reload)).await?;
            if code != 0 {
                return Err(AppError::Internal(format!(
                    "reload command exited with status {code}: {out}"
                )));
            }
            journal(state, job_id, "reload", "ok", "Reload command succeeded").await?;
        }
    }

    journal(state, job_id, "done", "ok", "Deployment completed").await?;
    Ok(())
}

/// Décide du mode d'élévation à partir du réglage de la cible et de celui de
/// l'application.
///
/// ENTRÉES : `target_use_sudo` / `target_staging_dir` valent None quand la
/// cible n'a rien de particulier et hérite de l'application — même convention
/// que les chemins de certificat. `app_use_sudo` / `app_staging_dir` sont les
/// valeurs du catalogue.
///
/// SORTIE : `Escalation::Direct` si personne ne demande sudo, sinon
/// `Escalation::Sudo` avec le répertoire de transit retenu.
fn resolve_escalation(
    target_use_sudo: Option<bool>,
    target_staging_dir: Option<&str>,
    app_use_sudo: bool,
    app_staging_dir: Option<&str>,
) -> Escalation {
    if !target_use_sudo.unwrap_or(app_use_sudo) {
        return Escalation::Direct;
    }
    let staging_dir = [target_staging_dir, app_staging_dir]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|d| !d.is_empty())
        .unwrap_or(DEFAULT_STAGING_DIR)
        .to_string();
    Escalation::Sudo { staging_dir }
}

/// Chemin de transit d'un fichier : le nom de base de la destination, préfixé
/// de l'identifiant du job pour que deux déploiements simultanés vers le même
/// hôte ne se marchent pas dessus.
fn staged_path(staging_dir: &str, dest_path: &str, job_id: &str) -> String {
    let base = dest_path.rsplit('/').next().unwrap_or(dest_path);
    let base = if base.is_empty() { "file" } else { base };
    format!("{}/{}.{}", staging_dir.trim_end_matches('/'), job_id, base)
}

/// Commande d'écriture d'un fichier, dont le contenu arrive sur l'entrée
/// standard du canal SSH.
///
/// En mode direct, on écrit à destination puis on pose le mode. En mode sudo,
/// on écrit dans le transit, `sudo install` pose le fichier avec son
/// propriétaire et son mode, et le transit est effacé **quoi qu'il arrive** :
/// une clé privée ne doit pas rester dans un répertoire non privilégié parce
/// que l'installation a échoué. Le code de retour conservé est celui de
/// l'installation, pas celui de l'effacement.
fn upload_command(escalation: &Escalation, dest_path: &str, mode: &str, job_id: &str) -> String {
    let dest = shell_quote(dest_path);
    match escalation {
        Escalation::Direct => format!("umask 077; cat > {dest} && chmod {mode} {dest}"),
        Escalation::Sudo { staging_dir } => {
            let staged = shell_quote(&staged_path(staging_dir, dest_path, job_id));
            format!(
                "umask 077; cat > {staged} && sudo -n install -o root -g root -m {mode} {staged} {dest}; \
rc=$?; rm -f {staged}; exit $rc"
            )
        }
    }
}

/// Enveloppe une commande d'exploitation (le rechargement du service) dans
/// l'élévation demandée.
///
/// La commande passe entière par `sudo -n sh -c` et non préfixée d'un simple
/// `sudo` : une commande composée — `nginx -t && systemctl reload nginx` — ne
/// verrait sinon que sa première moitié élevée. `-n` interdit toute invite de
/// mot de passe : sans lui, un sudoers exigeant un mot de passe ferait attendre
/// la session SSH indéfiniment plutôt qu'échouer.
fn privileged_command(escalation: &Escalation, command: &str) -> String {
    match escalation {
        Escalation::Direct => command.to_string(),
        Escalation::Sudo { .. } => format!("sudo -n sh -c {}", shell_quote(command)),
    }
}

async fn resolve_target(
    state: &AppState,
    host_application_id: &str,
) -> Result<ResolvedTarget, AppError> {
    let row: Option<DeployTargetRow> = sqlx::query_as(
        "SELECT m.hostname, m.ip_address, \
         ha.cert_path, ha.key_path, ha.chain_path, ha.reload_command, \
         app.default_cert_path, app.default_key_path, app.default_chain_path, app.default_reload_command, \
         ha.tls_key_id, \
         ha.use_sudo, ha.staging_dir, app.default_use_sudo, app.default_staging_dir, \
         c.kind AS cred_kind, c.username AS cred_username, c.secret_enc AS cred_secret_enc, \
         c.ssh_private_key_enc AS cred_ssh_private_key_enc, c.ssh_passphrase_enc AS cred_ssh_passphrase_enc, \
         hc.port AS ssh_port \
         FROM host_applications ha \
         JOIN machines m ON m.id = ha.machine_id \
         JOIN applications app ON app.id = ha.application_id \
         LEFT JOIN credentials c ON c.id = COALESCE( \
             ha.credential_id, \
             (SELECT credential_id FROM host_credentials \
              WHERE machine_id = ha.machine_id AND protocol = 'ssh' \
              ORDER BY is_default DESC, created_at ASC LIMIT 1)) \
         LEFT JOIN host_credentials hc ON hc.credential_id = c.id AND hc.machine_id = ha.machine_id AND hc.protocol = 'ssh' \
         WHERE ha.id = ?",
    )
    .bind(host_application_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or(AppError::NotFound)?;

    let cert_path = row
        .cert_path
        .clone()
        .or(row.default_cert_path.clone())
        .ok_or_else(|| AppError::Validation("no certificate path configured".to_string()))?;
    let key_path = row
        .key_path
        .clone()
        .or(row.default_key_path.clone())
        .ok_or_else(|| AppError::Validation("no key path configured".to_string()))?;
    let chain_path = row.chain_path.clone().or(row.default_chain_path.clone());
    let reload_command = row
        .reload_command
        .clone()
        .or(row.default_reload_command.clone());
    let escalation = resolve_escalation(
        row.use_sudo,
        row.staging_dir.as_deref(),
        row.default_use_sudo,
        row.default_staging_dir.as_deref(),
    );

    let tls_key_id = row.tls_key_id.clone().ok_or_else(|| {
        AppError::Validation("no certificate bound to this deployment target".to_string())
    })?;

    let cert_row: Option<(String, String, Option<String>, i32)> = sqlx::query_as(
        "SELECT cert_pem, private_key_enc, parent_cert_id, root_ca_id FROM tls_keys WHERE id = ?",
    )
    .bind(&tls_key_id)
    .fetch_optional(&state.pool)
    .await?;
    let (cert_pem, key_enc, parent_cert_id, root_ca_id) = cert_row.ok_or(AppError::NotFound)?;
    let key_pem = decrypt_secret(&state.cfg, &key_enc)?;

    let chain_pem = if chain_path.is_some() {
        build_chain_pem(state, parent_cert_id, root_ca_id).await?
    } else {
        None
    };

    let username = row
        .cred_username
        .clone()
        .ok_or_else(|| AppError::Validation("push credential has no username".to_string()))?;
    let kind = row.cred_kind.clone().ok_or_else(|| {
        AppError::Validation("no SSH credential available for this host".to_string())
    })?;

    let auth = match kind.as_str() {
        "ssh_key" => {
            let enc = row.cred_ssh_private_key_enc.clone().ok_or_else(|| {
                AppError::Validation("credential has no SSH private key".to_string())
            })?;
            let private_key_pem = decrypt_secret(&state.cfg, &enc)?;
            let passphrase = match row.cred_ssh_passphrase_enc.clone() {
                Some(p) => Some(decrypt_secret(&state.cfg, &p)?),
                None => None,
            };
            SshAuth::Key {
                private_key_pem,
                passphrase,
            }
        }
        "ssh_password" => {
            let enc = row
                .cred_secret_enc
                .clone()
                .ok_or_else(|| AppError::Validation("credential has no password".to_string()))?;
            SshAuth::Password(decrypt_secret(&state.cfg, &enc)?)
        }
        other => {
            return Err(AppError::Validation(format!(
                "credential kind '{other}' cannot be used for SSH deployment"
            )))
        }
    };

    let host = if row.ip_address.trim().is_empty() {
        row.hostname.clone()
    } else {
        row.ip_address.clone()
    };
    let port = row.ssh_port.unwrap_or(22).clamp(1, 65535) as u16;

    Ok(ResolvedTarget {
        cert_path,
        key_path,
        chain_path,
        reload_command,
        cert_pem,
        chain_pem,
        key_pem,
        host,
        port,
        username,
        auth,
        escalation,
    })
}

async fn build_chain_pem(
    state: &AppState,
    parent_cert_id: Option<String>,
    root_ca_id: i32,
) -> Result<Option<String>, AppError> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(parent_id) = parent_cert_id {
        let parent: Option<(String,)> =
            sqlx::query_as("SELECT cert_pem FROM tls_keys WHERE id = ?")
                .bind(&parent_id)
                .fetch_optional(&state.pool)
                .await?;
        if let Some((pem,)) = parent {
            parts.push(pem);
        }
    }
    let root: Option<(String,)> = sqlx::query_as("SELECT cert_pem FROM root_ca WHERE id = ?")
        .bind(root_ca_id)
        .fetch_optional(&state.pool)
        .await?;
    if let Some((pem,)) = root {
        parts.push(pem);
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        parts
            .iter()
            .map(|p| p.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    ))
}

struct ClientHandler;

#[async_trait::async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Internal-lab tool: accept the host key. Host-key pinning is a future enhancement.
        Ok(true)
    }
}

async fn connect(
    host: &str,
    port: u16,
    username: &str,
    auth: &SshAuth,
) -> Result<client::Handle<ClientHandler>, AppError> {
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect(config, (host, port), ClientHandler)
        .await
        .map_err(|e| AppError::Internal(format!("SSH connect failed: {e}")))?;

    let authenticated = match auth {
        SshAuth::Key {
            private_key_pem,
            passphrase,
        } => {
            let key = russh_keys::decode_secret_key(private_key_pem, passphrase.as_deref())
                .map_err(|e| AppError::Internal(format!("invalid SSH private key: {e}")))?;
            handle
                .authenticate_publickey(username, Arc::new(key))
                .await
                .map_err(|e| AppError::Internal(format!("SSH key auth error: {e}")))?
        }
        SshAuth::Password(pw) => handle
            .authenticate_password(username, pw)
            .await
            .map_err(|e| AppError::Internal(format!("SSH password auth error: {e}")))?,
    };

    if !authenticated {
        return Err(AppError::Internal(
            "SSH authentication rejected".to_string(),
        ));
    }
    Ok(handle)
}

struct HostSsh {
    host: String,
    port: u16,
    username: String,
    auth: SshAuth,
}

#[derive(sqlx::FromRow)]
struct HostSshRow {
    hostname: String,
    ip_address: String,
    port: Option<i32>,
    kind: String,
    username: Option<String>,
    secret_enc: Option<String>,
    ssh_private_key_enc: Option<String>,
    ssh_passphrase_enc: Option<String>,
}

async fn resolve_host_ssh(state: &AppState, machine_id: &str) -> Result<HostSsh, AppError> {
    let row: Option<HostSshRow> = sqlx::query_as(
        "SELECT m.hostname, m.ip_address, hc.port, c.kind, c.username, c.secret_enc, \
         c.ssh_private_key_enc, c.ssh_passphrase_enc \
         FROM machines m \
         JOIN host_credentials hc ON hc.machine_id = m.id AND hc.protocol = 'ssh' \
         JOIN credentials c ON c.id = hc.credential_id \
         WHERE m.id = ? ORDER BY hc.is_default DESC, hc.created_at ASC LIMIT 1",
    )
    .bind(machine_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row
        .ok_or_else(|| AppError::Validation("no SSH credential linked to this host".to_string()))?;
    let hostname = row.hostname;
    let ip_address = row.ip_address;
    let port = row.port;
    let kind = row.kind;
    let secret_enc = row.secret_enc;
    let key_enc = row.ssh_private_key_enc;
    let pass_enc = row.ssh_passphrase_enc;

    let username = row
        .username
        .ok_or_else(|| AppError::Validation("credential has no username".to_string()))?;
    let auth = match kind.as_str() {
        "ssh_key" => {
            let enc = key_enc.ok_or_else(|| {
                AppError::Validation("credential has no SSH private key".to_string())
            })?;
            let private_key_pem = decrypt_secret(&state.cfg, &enc)?;
            let passphrase = match pass_enc {
                Some(p) => Some(decrypt_secret(&state.cfg, &p)?),
                None => None,
            };
            SshAuth::Key {
                private_key_pem,
                passphrase,
            }
        }
        "ssh_password" => {
            let enc = secret_enc
                .ok_or_else(|| AppError::Validation("credential has no password".to_string()))?;
            SshAuth::Password(decrypt_secret(&state.cfg, &enc)?)
        }
        other => {
            return Err(AppError::Validation(format!(
                "credential kind '{other}' cannot be used for SSH"
            )))
        }
    };

    let host = if ip_address.trim().is_empty() {
        hostname
    } else {
        ip_address
    };
    Ok(HostSsh {
        host,
        port: port.unwrap_or(22).clamp(1, 65535) as u16,
        username,
        auth,
    })
}

async fn exec_command(
    handle: &client::Handle<ClientHandler>,
    command: &str,
) -> Result<(i32, String), AppError> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| AppError::Internal(format!("channel open failed: {e}")))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| AppError::Internal(format!("exec failed: {e}")))?;
    let mut output = String::new();
    let mut code: i32 = -1;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => output.push_str(&String::from_utf8_lossy(data)),
            ChannelMsg::ExtendedData { ref data, .. } => {
                output.push_str(&String::from_utf8_lossy(data))
            }
            ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
            // Ne pas sortir sur Eof. Le serveur envoie « eof » et
            // « exit-status » sans ordre garanti, et OpenSSH envoie souvent eof
            // en premier : sortir là laissait le code de retour à -1 alors que
            // la commande avait réussi et que sa sortie était déjà lue. Toute
            // vérification de la forme « code != 0 || sortie ne contient pas OK »
            // échouait donc en rendant un message trompeur — « répertoire non
            // accessible en écriture » pour un répertoire parfaitement
            // accessible. RFC 4254 place exit-status avant close ; sortir sur
            // close est donc sûr et borné.
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok((code, output))
}

#[allow(clippy::too_many_arguments)]
async fn write_remote_file(
    state: &AppState,
    job_id: &str,
    handle: &client::Handle<ClientHandler>,
    escalation: &Escalation,
    path: &str,
    data: &[u8],
    mode: &str,
    label: &str,
) -> Result<(), AppError> {
    journal(
        state,
        job_id,
        "upload",
        "running",
        &format!("Writing {label} to {path}"),
    )
    .await?;
    let command = upload_command(escalation, path, mode, job_id);
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| AppError::Internal(format!("channel open failed: {e}")))?;
    channel
        .exec(true, command.as_str())
        .await
        .map_err(|e| AppError::Internal(format!("exec failed: {e}")))?;
    channel
        .data(data)
        .await
        .map_err(|e| AppError::Internal(format!("data write failed: {e}")))?;
    channel
        .eof()
        .await
        .map_err(|e| AppError::Internal(format!("eof failed: {e}")))?;

    let mut code: i32 = -1;
    let mut stderr = String::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExtendedData { ref data, .. } => {
                stderr.push_str(&String::from_utf8_lossy(data))
            }
            ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if code != 0 {
        return Err(AppError::Internal(format!(
            "writing {label} to {path} failed (status {code}): {stderr}"
        )));
    }
    journal(
        state,
        job_id,
        "upload",
        "ok",
        &format!("Wrote {label} to {path}"),
    )
    .await?;
    Ok(())
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => path[..idx].to_string(),
        None => ".".to_string(),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// ---- Certbot (remote Let's Encrypt issuance / renewal) ----

#[derive(sqlx::FromRow)]
struct CertbotRow {
    machine_id: String,
    domains: String,
    email: Option<String>,
    challenge: String,
    webroot_path: Option<String>,
    dns_plugin: Option<String>,
    extra_args: Option<String>,
    staging: bool,
    live_cert_path: Option<String>,
}

pub async fn run_certbot(
    state: &AppState,
    certbot_config_id: &str,
    actor: &str,
) -> Result<DeployResult, AppError> {
    let job_id = start_certbot_job(state, certbot_config_id, actor).await?;
    let result = run_certbot_inner(state, certbot_config_id, &job_id).await;
    match result {
        Ok(not_after) => {
            finish_job(state, &job_id, "success").await?;
            update_certbot_status(state, certbot_config_id, "success", not_after).await?;
            Ok(DeployResult {
                job_id,
                status: "success".to_string(),
            })
        }
        Err(e) => {
            journal(state, &job_id, "error", "failed", &e.to_string()).await?;
            finish_job(state, &job_id, "failed").await?;
            update_certbot_status(state, certbot_config_id, "failed", None).await?;
            Ok(DeployResult {
                job_id,
                status: "failed".to_string(),
            })
        }
    }
}

async fn run_certbot_inner(
    state: &AppState,
    certbot_config_id: &str,
    job_id: &str,
) -> Result<Option<chrono::NaiveDateTime>, AppError> {
    let cfg: Option<CertbotRow> = sqlx::query_as(
        "SELECT machine_id, domains, email, challenge, webroot_path, dns_plugin, extra_args, \
         staging, live_cert_path FROM certbot_configs WHERE id = ?",
    )
    .bind(certbot_config_id)
    .fetch_optional(&state.pool)
    .await?;
    let cfg = cfg.ok_or(AppError::NotFound)?;

    let domains: Vec<String> = cfg
        .domains
        .split(',')
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if domains.is_empty() {
        return Err(AppError::Validation("no domains configured".to_string()));
    }

    journal(
        state,
        job_id,
        "connect",
        "running",
        "Opening SSH connection",
    )
    .await?;
    let conn = resolve_host_ssh(state, &cfg.machine_id).await?;
    let handle = connect(&conn.host, conn.port, &conn.username, &conn.auth).await?;
    journal(state, job_id, "connect", "ok", "Authenticated over SSH").await?;

    let mut cmd = String::from("certbot certonly --non-interactive --agree-tos");
    match cfg.challenge.as_str() {
        "webroot" => {
            let path = cfg.webroot_path.clone().ok_or_else(|| {
                AppError::Validation("webroot challenge needs a webroot path".to_string())
            })?;
            cmd.push_str(&format!(" --webroot -w {}", shell_quote(&path)));
        }
        "standalone" => cmd.push_str(" --standalone"),
        "nginx" => cmd.push_str(" --nginx"),
        "apache" => cmd.push_str(" --apache"),
        "dns" => {
            let plugin = cfg.dns_plugin.clone().ok_or_else(|| {
                AppError::Validation("dns challenge needs a dns plugin".to_string())
            })?;
            cmd.push_str(&format!(" --dns-{}", plugin));
        }
        other => {
            return Err(AppError::Validation(format!(
                "unsupported certbot challenge '{other}'"
            )))
        }
    }
    match cfg.email.as_deref() {
        Some(e) if !e.trim().is_empty() => cmd.push_str(&format!(" --email {}", shell_quote(e))),
        _ => cmd.push_str(" --register-unsafely-without-email"),
    }
    if cfg.staging {
        cmd.push_str(" --staging");
    }
    for d in &domains {
        cmd.push_str(&format!(" -d {}", shell_quote(d)));
    }
    if let Some(extra) = cfg.extra_args.as_deref() {
        if !extra.trim().is_empty() {
            cmd.push(' ');
            cmd.push_str(extra);
        }
    }

    journal(
        state,
        job_id,
        "certbot",
        "running",
        &format!("Running: {cmd}"),
    )
    .await?;
    let (code, out) = exec_command(&handle, &cmd).await?;
    let tail = out
        .chars()
        .rev()
        .take(1500)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    if code != 0 {
        return Err(AppError::Internal(format!(
            "certbot exited with status {code}: {tail}"
        )));
    }
    journal(
        state,
        job_id,
        "certbot",
        "ok",
        &format!("certbot succeeded: {tail}"),
    )
    .await?;

    // Best-effort read of the resulting certificate expiry for inventory/monitoring.
    let cert_path = cfg
        .live_cert_path
        .clone()
        .unwrap_or_else(|| format!("/etc/letsencrypt/live/{}/fullchain.pem", domains[0]));
    journal(
        state,
        job_id,
        "read_expiry",
        "running",
        &format!("Reading expiry from {cert_path}"),
    )
    .await?;
    let (ecode, eout) = exec_command(
        &handle,
        &format!(
            "openssl x509 -enddate -noout -in {}",
            shell_quote(&cert_path)
        ),
    )
    .await?;
    let not_after = if ecode == 0 {
        parse_openssl_enddate(&eout)
    } else {
        None
    };
    match not_after {
        Some(dt) => {
            journal(
                state,
                job_id,
                "read_expiry",
                "ok",
                &format!("Certificate valid until {dt} UTC"),
            )
            .await?
        }
        None => {
            journal(
                state,
                job_id,
                "read_expiry",
                "warn",
                "Could not read certificate expiry",
            )
            .await?
        }
    }

    journal(state, job_id, "done", "ok", "Certbot run completed").await?;
    Ok(not_after)
}

fn parse_openssl_enddate(output: &str) -> Option<chrono::NaiveDateTime> {
    let line = output.lines().find(|l| l.contains("notAfter="))?;
    let value = line.split("notAfter=").nth(1)?.trim();
    chrono::NaiveDateTime::parse_from_str(value, "%b %e %H:%M:%S %Y GMT").ok()
}

async fn start_certbot_job(
    state: &AppState,
    certbot_config_id: &str,
    actor: &str,
) -> Result<String, AppError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO deployment_jobs (id, host_application_id, certbot_config_id, trigger_source, status, job_type, started_at, created_by, created_at) \
         VALUES (?, NULL, ?, 'manual', 'running', 'certbot', ?, ?, ?)",
    )
    .bind(&id)
    .bind(certbot_config_id)
    .bind(now)
    .bind(actor)
    .bind(now)
    .execute(&state.pool)
    .await?;
    Ok(id)
}

async fn update_certbot_status(
    state: &AppState,
    certbot_config_id: &str,
    status: &str,
    not_after: Option<chrono::NaiveDateTime>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE certbot_configs SET last_run_status = ?, last_run_at = ?, last_not_after = COALESCE(?, last_not_after), updated_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(Utc::now().naive_utc())
    .bind(not_after)
    .bind(Utc::now().naive_utc())
    .bind(certbot_config_id)
    .execute(&state.pool)
    .await?;
    Ok(())
}

// ---- Journal / job bookkeeping ----

async fn start_job(
    state: &AppState,
    host_application_id: &str,
    trigger: &str,
    job_type: &str,
    actor: &str,
) -> Result<String, AppError> {
    let tls_key_id: Option<(Option<String>,)> =
        sqlx::query_as("SELECT tls_key_id FROM host_applications WHERE id = ?")
            .bind(host_application_id)
            .fetch_optional(&state.pool)
            .await?;
    let bound_cert = tls_key_id.and_then(|r| r.0);

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO deployment_jobs (id, host_application_id, tls_key_id, trigger_source, status, job_type, started_at, created_by, created_at) \
         VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(host_application_id)
    .bind(&bound_cert)
    .bind(trigger)
    .bind(job_type)
    .bind(now)
    .bind(actor)
    .bind(now)
    .execute(&state.pool)
    .await?;
    Ok(id)
}

async fn finish_job(state: &AppState, job_id: &str, status: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE deployment_jobs SET status = ?, finished_at = ? WHERE id = ?")
        .bind(status)
        .bind(Utc::now().naive_utc())
        .bind(job_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

async fn journal(
    state: &AppState,
    job_id: &str,
    step: &str,
    status: &str,
    message: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO deployment_journal (id, job_id, step, status, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(job_id)
    .bind(step)
    .bind(status)
    .bind(message)
    .bind(Utc::now().naive_utc())
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn update_host_app_status(
    state: &AppState,
    host_application_id: &str,
    status: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE host_applications SET last_deploy_status = ?, last_deploy_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(Utc::now().naive_utc())
    .bind(host_application_id)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn send_failure_alert(state: &AppState, host_application_id: &str, error: &str) {
    let email_to = match resolve_alert_email(state, host_application_id).await {
        Ok(Some(addr)) => addr,
        _ => return,
    };
    let payload = json!({
        "type": "deployment_failure",
        "host_application_id": host_application_id,
        "error": error,
        "timestamp": Utc::now(),
    });
    if let Err(e) =
        crate::notifier::send_email(&email_to, "[Akamana] Deployment failed", &payload).await
    {
        tracing::warn!("failed to send deployment failure alert: {e}");
    }
}

async fn resolve_alert_email(
    state: &AppState,
    host_application_id: &str,
) -> Result<Option<String>, AppError> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT m.alert_email FROM host_applications ha JOIN machines m ON m.id = ha.machine_id WHERE ha.id = ?",
    )
    .bind(host_application_id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((Some(addr),)) = row {
        if !addr.trim().is_empty() {
            return Ok(Some(addr));
        }
    }
    let default: Option<(String,)> =
        sqlx::query_as("SELECT value_text FROM settings WHERE key_name = 'default_alert_email'")
            .fetch_optional(&state.pool)
            .await?;
    Ok(default.map(|r| r.0).filter(|s| !s.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_defaults_to_direct() {
        assert_eq!(
            resolve_escalation(None, None, false, None),
            Escalation::Direct
        );
    }

    #[test]
    fn application_default_applies_when_target_is_silent() {
        assert_eq!(
            resolve_escalation(None, None, true, None),
            Escalation::Sudo {
                staging_dir: DEFAULT_STAGING_DIR.to_string()
            }
        );
    }

    #[test]
    fn target_can_turn_sudo_off_against_the_application_default() {
        assert_eq!(
            resolve_escalation(Some(false), None, true, Some("/var/tmp/akamana")),
            Escalation::Direct
        );
    }

    #[test]
    fn target_staging_dir_wins_and_blanks_are_ignored() {
        assert_eq!(
            resolve_escalation(Some(true), Some("  "), false, Some("/var/tmp/akamana")),
            Escalation::Sudo {
                staging_dir: "/var/tmp/akamana".to_string()
            }
        );
        assert_eq!(
            resolve_escalation(
                Some(true),
                Some("/home/deploy/tmp"),
                false,
                Some("/var/tmp")
            ),
            Escalation::Sudo {
                staging_dir: "/home/deploy/tmp".to_string()
            }
        );
    }

    #[test]
    fn staged_path_keeps_the_basename_and_isolates_jobs() {
        assert_eq!(
            staged_path("/var/tmp/akamana", "/etc/nginx/certs/site.crt", "job-1"),
            "/var/tmp/akamana/job-1.site.crt"
        );
        // Un répertoire avec barre finale ne doit pas produire un double slash.
        assert_eq!(
            staged_path(".akamana-staging/", "/etc/ssl/private/site.key", "job-2"),
            ".akamana-staging/job-2.site.key"
        );
    }

    #[test]
    fn direct_upload_is_unchanged() {
        assert_eq!(
            upload_command(&Escalation::Direct, "/etc/nginx/site.crt", "644", "job-1"),
            "umask 077; cat > '/etc/nginx/site.crt' && chmod 644 '/etc/nginx/site.crt'"
        );
    }

    #[test]
    fn sudo_upload_stages_installs_and_always_cleans_up() {
        let escalation = Escalation::Sudo {
            staging_dir: "/var/tmp/akamana".to_string(),
        };
        let cmd = upload_command(&escalation, "/etc/ssl/private/site.key", "600", "job-1");
        assert!(cmd.contains("cat > '/var/tmp/akamana/job-1.site.key'"));
        assert!(cmd.contains(
            "sudo -n install -o root -g root -m 600 '/var/tmp/akamana/job-1.site.key' '/etc/ssl/private/site.key'"
        ));
        // Le nettoyage suit un point-virgule, pas un && : il doit avoir lieu même
        // si l'installation échoue, sinon une clé privée reste en clair dans un
        // répertoire non privilégié.
        assert!(cmd.contains("; rc=$?; rm -f '/var/tmp/akamana/job-1.site.key'; exit $rc"));
    }

    #[test]
    fn compound_reload_commands_are_elevated_as_a_whole() {
        let escalation = Escalation::Sudo {
            staging_dir: ".akamana-staging".to_string(),
        };
        assert_eq!(
            privileged_command(&escalation, "nginx -t && systemctl reload nginx"),
            "sudo -n sh -c 'nginx -t && systemctl reload nginx'"
        );
        assert_eq!(
            privileged_command(&Escalation::Direct, "systemctl reload nginx"),
            "systemctl reload nginx"
        );
    }

    #[test]
    fn single_quotes_in_a_reload_command_survive_the_wrapping() {
        let escalation = Escalation::Sudo {
            staging_dir: ".akamana-staging".to_string(),
        };
        assert_eq!(
            privileged_command(&escalation, "echo 'ok'"),
            r#"sudo -n sh -c 'echo '\''ok'\'''"#
        );
    }
}
