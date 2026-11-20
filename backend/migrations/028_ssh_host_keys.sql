-- Épingles de clés d'hôte SSH (TOFU). Akamana se connecte en SSH pour
-- déployer des certificats et pousser des sauvegardes : sans vérification de
-- la clé d'hôte, un intercepteur recevait la clé privée du service et les
-- identifiants SSH. La première connexion enregistre la clé, les suivantes
-- doivent présenter la même. Un serveur réinstallé : supprimer la ligne.
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    id CHAR(36) PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    key_type VARCHAR(64) NOT NULL,
    public_key_b64 TEXT NOT NULL,
    fingerprint VARCHAR(128) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE KEY uniq_ssh_host_key (host, port)
)
