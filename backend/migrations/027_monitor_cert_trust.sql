-- Verdict de confiance du certificat observé par la supervision : auto-signé ?
-- reconnu par le magasin système ? émis par une CA gérée ici ? Un JSON plutôt
-- que trois colonnes : le détail (raison du refus, CA reconnue) l'accompagne.
ALTER TABLE machine_monitor_ports ADD COLUMN IF NOT EXISTS cert_trust_json TEXT NULL
