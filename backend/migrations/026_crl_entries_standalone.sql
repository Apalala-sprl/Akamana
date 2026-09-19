-- La CRL survit à la suppression du certificat. Une entrée de révocation
-- doit rester publiée jusqu'à l'expiration du certificat : un client qui
-- possède encore le cert ne doit pas redevenir de confiance parce que
-- l'opérateur a fait le ménage. La clé étrangère vers tls_keys empêchait
-- justement de supprimer un certificat révoqué (« database operation
-- failed »). On mémorise donc dans crl_entries ce dont la génération de
-- la CRL a besoin — la CA émettrice et l'expiration — et on retire la FK.
ALTER TABLE crl_entries ADD COLUMN IF NOT EXISTS root_ca_id INT NULL;
ALTER TABLE crl_entries ADD COLUMN IF NOT EXISTS not_after DATETIME NULL;
UPDATE crl_entries ce JOIN tls_keys tk ON tk.id = ce.tls_key_id SET ce.root_ca_id = tk.root_ca_id, ce.not_after = tk.valid_to WHERE ce.root_ca_id IS NULL;
ALTER TABLE crl_entries DROP FOREIGN KEY IF EXISTS fk_crl_tls_key;
ALTER TABLE crl_entries ADD INDEX IF NOT EXISTS idx_crl_root_ca (root_ca_id)
