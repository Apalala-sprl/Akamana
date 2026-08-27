# Akamana — Backup & Restore

> New document (2026-07-15): this subsystem (modules `backup.rs`, `backup_crypto.rs`,
> `backup_remote.rs`, migration `020_backup_recipients.sql`) was previously undocumented.

## 1. Overview

Akamana backs up its **entire MariaDB database** as a logical SQL dump, optionally
encrypted into a self-describing `.ezbak` container, kept locally under
`$AKAMANA_DATA_DIR/backups/` and optionally pushed **off-box** (mounted path or SFTP).
Backups run on demand (API/UI) or on a schedule (background task started at boot).
All operations are **full_admin only** and audited.

The dump is produced with `mariadb-dump --skip-dump-date --single-transaction
--routines` (the `default-mysql-client` package is installed in the image for this),
restore uses the `mariadb` client. Note the dump contains everything — including
encrypted private keys, whose plaintext still requires `KEY_ENCRYPTION_KEY_B64` from the
environment; a backup alone is not sufficient to rebuild an instance.

## 2. Local backups

- Directory: `$AKAMANA_DATA_DIR/backups` (default `/data/backups`).
- File names: `akamana-<timestamp>.sql` or `akamana-<timestamp>.sql.ezbak`; a `<name>.sig`
  companion stores the change-detection signature.
- **Skip-if-unchanged**: before writing, a SHA-256 signature of a dump that *excludes
  high-churn log tables* (`access_logs`, `audit_logs`, `security_events`,
  `notification_events`, `deployment_jobs`, `deployment_journal`) is compared with the
  latest backup's `.sig`; if identical, no new file is written.
- **Retention**: the newest N files are kept (setting `backup_retention`, default 5).

## 3. Encryption — the `.ezbak` container

Layout: `EZBAK1\n` magic → one-line JSON header → `\n` → ciphertext.
Plaintext is gzip-compressed then encrypted with **AES-256-GCM**. Two key modes:

- **Passphrase**: the 256-bit key is derived with **Argon2id**
  (m=19456, t=2, p=1 — parameters and salt recorded in the header, so backups remain
  decryptable independently of build defaults). The passphrase itself is stored
  encrypted (`backup_passphrase_enc`, AES-256-GCM under the instance KEK).
- **Envelope**: a random data key (DEK) encrypts the backup and is wrapped (RSA) for
  each registered **recipient public key** (`backup_recipients` table: name, public key,
  fingerprint). Any one recipient private key can decrypt.

The format is self-describing: a backup can be restored on a **different** instance
given the passphrase or a recipient private key.

## 4. Off-box destinations (`backup_remote.rs`)

Two destination types, configured in Settings (per feature — see §6):

- **Path** — a local/mounted directory (covers NFS or SMB/CIFS shares mounted by the
  OS/container).
- **SFTP** — pure-Rust (russh/russh-sftp, no system `ssh` binary); auth by password or
  private key (+ optional passphrase); own retention applied remotely
  (`akamana-` prefix).

> ⚠️ **SFTP host-key pinning is not enforced** (any server key is accepted, mirroring
> `deploy.rs`). Acceptable on a trusted lab network only; pin host keys before wider use.

The same remote machinery is reused by two other publishers:

- **CRL publishing** — pushes the DER CRL (also served live at `GET /crl/<root_id>.crl`,
  the URL embedded in issued certificates' CRL Distribution Point) to a remote web
  location (`settings/crl/remote`, `POST /api/v1/crl/publish`).
- **Deploy-HTML publishing** — generates a public HTML page with root-CA download and
  install instructions and pushes it to a remote web root
  (`settings/deploy-html/remote`, preview + publish endpoints; filename setting
  `deploy_html_filename`, default `index.html`).

## 5. API endpoints (all full_admin, bearer-authenticated)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/backup/export` | download a fresh dump (plaintext or encrypted per settings) |
| POST | `/api/v1/backup/import` | upload & restore a dump (`.sql` or `.ezbak`) |
| POST | `/api/v1/backup/run` | run a backup now (honors skip-unchanged, retention, remote push) |
| GET | `/api/v1/backup/list` | list local backup files |
| POST | `/api/v1/backup/restore` | restore from an existing local backup |
| GET/POST | `/api/v1/backup/recipients` | list / add envelope recipients |
| DELETE | `/api/v1/backup/recipients/:id` | remove a recipient |
| GET/PUT | `/api/v1/settings/backup` | schedule, retention, skip-unchanged, encryption mode, passphrase |
| GET/PUT | `/api/v1/settings/backup/remote` | off-box destination |
| POST | `/api/v1/backup/remote/test` | connectivity test |
| GET/PUT | `/api/v1/settings/crl/remote` · POST `/api/v1/crl/remote/test` · POST `/api/v1/crl/publish` | CRL publishing |
| GET/PUT | `/api/v1/settings/deploy-html/remote` · POST `/api/v1/deploy-html/remote/test` · GET `/api/v1/deploy-html/preview` · POST `/api/v1/deploy-html/publish` | root-CA install page publishing |

## 6. Settings keys (table `settings`)

| Key | Default | Meaning |
|---|---|---|
| `backup_enabled` | `false` | enable the scheduled backup task |
| `backup_frequency_hours` | `24` | schedule period |
| `backup_retention` | `5` | local files kept |
| `backup_skip_unchanged` | `true` | skip when nothing meaningful changed |
| `backup_encryption_mode` | — | `none` / `passphrase` / `envelope` |
| `backup_passphrase_enc` | — | passphrase, encrypted under the instance KEK |
| `deploy_html_filename` | `index.html` | published page name |
| *(per feature `backup` / `crl` / `deploy_html`)* remote dest keys | — | dest type (`none`/`path`/`sftp`), host/port/user/auth, directory, retention |

## 7. Restore & disaster-recovery notes

1. Restoring **replaces** database content (`mariadb` executes the dump against the
   configured database) — take a fresh export first.
2. To rebuild elsewhere you need: a backup file **+** its passphrase or a recipient
   private key (if encrypted) **+** the original `KEY_ENCRYPTION_KEY_B64` (and
   `JWT_SECRET` to keep sessions/token semantics).
3. After a restore, restart the service so migrations re-verify and background tasks
   pick up fresh state.
4. Backups do **not** include `/data` files (addons, crypto_options.json) — keep those
   in configuration management or host backups.
