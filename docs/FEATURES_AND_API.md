# EZKey — Features, API & Change Log

This document describes the EZKey feature set, the full HTTP API surface, the data model,
and the improvements delivered during the 2026‑05 expansion. It complements the focused
docs in this folder (`api_reference.md`, `database_tables.md`, `security.md`, etc.).

---

## 1. Overview

EZKey is an internal‑lab **certificate & key lifecycle service**. It runs as a single Rust
(Axum/SQLx/OpenSSL) binary behind nginx, backed by MariaDB, with a classless vanilla‑JS SPA.
It lets operators who are not crypto experts safely:

- Run an internal **Certificate Authority** (root → intermediate → leaf) and issue TLS/SSH material.
- **Monitor** certificates exposed on hosts/ports (and per virtual host).
- **Discover** hosts on the local network.
- **Deploy** certificates to servers over SSH and **auto‑renew** them.
- Obtain public certificates via **certbot** run remotely over SSH.

### Authentication & roles
- `POST /api/v1/auth/login` returns a JWT bearer token (`AUTH_MODE=local`, HS256) — or OIDC (RS256) when configured.
- All `/api/v1/*` endpoints require `Authorization: Bearer <token>` except the public allow‑list:
  `/health`, `/api/v1/auth/login`, `GET /api/v1/certificates/root`, and `GET /api/v1/certificates/root/download/:platform`.
- Roles: **full_admin**, **tls_admin**, **ssh_admin**, **auditor**. Authorization is enforced per‑handler:
  - `tls_admin`/`full_admin` → TLS certs, CA, certbot, auto‑renew.
  - `ssh_admin`/`full_admin` → SSH keys.
  - any of tls/ssh/full → machines, monitoring, hosts, applications, host links, network scan.
  - **full_admin only** → credentials (secret material), users, default settings.
  - `auditor`/`full_admin` → logs/audit.

### Dual‑mode UX
A header toggle switches **Standard** (guided, with `.explain` panels, a first‑run CA explainer,
recommended key‑type defaults and pros/cons) and **Expert** (explanations hidden, compact). The
choice persists in `localStorage`.

---

## 2. Feature areas

### 2.1 Certificate Authority & issuance
- Create an **Organization + Root CA** with a configurable validity, cipher and key length.
- **Per‑root Subject DN**: Country / State / Locality / Organization / OU are stored on the root
  and **inherited by every issued certificate** (leaf & intermediate) — the DN is genuinely linked
  to the root cert. Preserved across root renewal.
- Cipher support: **Ed25519** (recommended, fixed 256‑bit), **ECDSA P‑256** (fixed), **RSA**
  (2048/3072/4096 — only RSA has a meaningful key‑length choice; the UI adapts the length options
  to the chosen cipher). Defaults configured in Settings are applied to the issuance dialogs.
- Collapsible **certificate tree** (root → intermediate → leaf) with colour‑coded expiry badges.
- Import existing certificates; renew; revoke (CRL); intermediate creation; export public/private;
  controlled root‑CA download per platform.

### 2.2 Monitoring (formerly "Machines")
- Hierarchical **host → port → virtual host (SNI)** editor: pick a host (or add one), edit its
  fields, and manage indented **ports** (+/‑) and per‑port **virtual hosts** (+/‑).
- The same port can be monitored for **several SNI virtual hosts** (unique on `machine_id, port, sni_host`).
- Background scanner connects via TLS (using the per‑row SNI override), records expiry/subject/
  issuer/chain, and colours rows by expiry. Per‑host **alert email** + global default; alerting
  performs a **reachability cross‑check** (don't alert if EZKey's own network is down).

### 2.3 Network discovery
- `POST /api/v1/network/scan` probes a private **/24** (default = the EZKey server's own network),
  **restricted to RFC1918** ranges (10/8, 172.16‑31, 192.168/16). Returns live hosts with
  hostname guessing via **reverse DNS → TLS certificate CN/SAN → NetBIOS**. Discovered hosts can be
  bulk‑added (each becomes a machine + a monitored port on the probed port).

### 2.4 Inventory: hosts, applications, credentials
- **Hosts** page: inventory table (Name / IP / OS type / Environment / Mode) with Add / Edit
  (rename, IP, OS, owner, env) / Delete / Manage (per‑host detail).
- **Applications** catalog (Nginx, Apache, Traefik, HAProxy, SSH, IIS, Kubernetes seeded) with
  default cert/key/chain paths, reload command and a config example.
- **Credentials** (SSH key/password, API token) — secrets **encrypted at rest**, never returned;
  can reuse an existing EZKey‑generated SSH key.
- Link tables: **host ↔ credential** and **host ↔ application** (deployment targets with per‑location
  cert/key paths and a push credential).
- **Owner & Environment** are dropdowns everywhere, backed by lists editable in Settings (+/‑ buttons).

### 2.5 Deployment engine (outbound SSH)
- `…/host-applications/:id/check` — pre‑flight: connect over SSH (russh) and verify the target dirs
  are writable, **without changing anything**.
- `…/host-applications/:id/deploy` — push cert/key/chain (shell‑quoted paths, `umask 077`), run the
  reload command, and journal every step. Email alert on failure.
- Full **journal** per job (`…/deployments/:job_id/journal`).

### 2.6 Lifecycle automation
- **Auto‑renew**: leaf certs flagged `auto_renew` are re‑issued within their `renew_days_before`
  window, deployment targets re‑pointed to the new cert, and auto‑deploy targets re‑deployed.
- **Remote certbot**: define a certbot config per host (challenge webroot/standalone/nginx/apache/dns,
  domains, email, staging) and run `certbot certonly` over SSH; the resulting expiry is recorded and
  auto‑renewed.

---

## 3. API reference

Method legend — auth required unless marked *(public)*. Bodies are JSON.

### Auth, health, crypto
| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | *(public)* liveness |
| POST | `/api/v1/auth/login` | *(public)* obtain JWT |
| GET | `/api/v1/crypto/options` | available ciphers / key lengths / cert levels |
| GET | `/api/v1/network/resolve` | DNS resolve helper |
| POST | `/api/v1/network/scan` | scan a private /24 for live hosts (RFC1918 only) |

### Certificate Authority & certificates
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/certificates/root` | *(public)* list roots |
| POST | `/api/v1/certificates/root` | create org + root CA (with DN, optional intermediate) |
| GET/DELETE | `/api/v1/certificates/root/:id` | get / delete root |
| POST | `/api/v1/certificates/root/:id/renew` | renew root (preserves DN) |
| POST | `/api/v1/certificates/root/:id/revoke` | revoke root |
| GET | `/api/v1/certificates/root/download/:platform` | *(public)* download root cert |
| POST | `/api/v1/certificates/intermediate` | create intermediate |
| GET | `/api/v1/certificates/tls` · `/ssh` · `/tree` | list / hierarchy |
| GET/DELETE | `/api/v1/certificates/tls/:id` · `/ssh/:id` | detail / delete |
| PATCH | `/api/v1/certificates/tls/:id/auto-renew` | toggle auto‑renew (+ days before) |
| PATCH | `/api/v1/certificates/{tls,ssh}/:id/publish-key` | allow private‑key export |
| POST | `/api/v1/certificates/{tls,ssh}/import` | import existing cert |
| GET | `/api/v1/certificates/{tls,ssh}/:id/export/{public,private}` | download |
| POST | `/api/v1/keys/tls` · `/keys/ssh` | generate leaf/SSH material |
| POST | `/api/v1/keys/tls/renew` · `/keys/ssh/revoke/:id` | renew / revoke |
| POST | `/api/v1/crl/revoke` · GET `/api/v1/crl` | revoke TLS / list CRL |

### Inventory & deployment
| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/v1/machines` | list / create host |
| PATCH/DELETE | `/api/v1/machines/:id` | edit (name/IP/owner/env/OS/alert/test/monitor‑only) / delete |
| GET | `/api/v1/machines/monitor` | monitored ports/vhosts with last status |
| POST | `/api/v1/machines/monitor/ports` | add monitored port/vhost (`sni_host`) |
| PATCH/DELETE | `/api/v1/machines/monitor/ports/:id` | edit / delete |
| POST | `/api/v1/machines/monitor/ports/:id/scan` · `/monitor/scan` | scan one / all |
| GET/POST | `/api/v1/applications` · PATCH/DELETE `/:id` | app catalog CRUD |
| GET/POST | `/api/v1/credentials` · PATCH/DELETE `/:id` | credentials (full_admin) |
| GET/POST | `/api/v1/host-credentials` · DELETE `/:id` | host↔credential links |
| GET/POST | `/api/v1/host-applications` · PATCH/DELETE `/:id` | host↔app deployment targets |
| POST | `/api/v1/host-applications/:id/check` | pre‑flight (no changes) |
| POST | `/api/v1/host-applications/:id/deploy` | SSH push + reload + journal |
| GET | `/api/v1/host-applications/:id/deployments` | job history |
| GET | `/api/v1/deployments/:job_id/journal` | step‑by‑step journal |
| POST | `/api/v1/deploy/tls/:id/guide` | generate manual deployment guide |
| GET | `/api/v1/integrations/addons` · POST `/integrations/plan` | declarative addons |

### Certbot
| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/v1/certbot/configs` | list / create certbot config |
| DELETE | `/api/v1/certbot/configs/:id` | delete |
| POST | `/api/v1/certbot/configs/:id/run` | run `certbot certonly` over SSH, record expiry |

### Users, settings, logs
| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/v1/users` · PATCH `/:id/role` · POST `/:id/password` · DELETE `/:id` | user admin (full_admin) |
| GET | `/api/v1/users/me` · POST `/me/password` · POST/DELETE `/me/picture` | self‑service |
| GET/PUT | `/api/v1/settings/defaults` | TLS/SSH defaults + owner/environment lists |
| GET/PUT | `/api/v1/settings/machine-monitor` · `/settings/notifications` · `/settings/siem` | settings |
| GET | `/api/v1/logs/actions` · `/logs/access` · `/logs/security` · `/audit` | logs (auditor/full_admin) |

---

## 4. Data model additions (migrations 011–015)

- `applications`, `credentials`, `host_credentials`, `host_applications`, `deployment_jobs`,
  `deployment_journal`, `certbot_configs` (011/012).
- `tls_keys`: `auto_renew`, `renew_days_before`, `last_status`, `last_status_at`.
- `machines`: `alert_email`, `test_url`, `monitor_only`, `os_type`.
- `root_ca`: `country`, `state`, `locality`, `org_unit` (subject DN).
- `machine_monitor_ports`: `sni_host` (+ unique key `machine_id, port, sni_host`).

> Migrations are `include_str!`'d and re‑run every startup; they must be idempotent
> (`IF [NOT] EXISTS`) and must not contain `;` inside statement bodies. Seed data with
> semicolons is inserted from `db.rs` via bound parameters.

---

## 5. Change log (2026‑05 expansion)

1. Inventory data model + seeded application catalog.
2. CRUD + UI for applications, credentials, host↔credential and host↔application links.
3. Collapsible certificate tree; per‑host view.
4. Outbound‑SSH **deployment engine** (russh) with pre‑flight checks + journaling.
5. **Lifecycle automation**: auto‑renew → re‑deploy; reachability cross‑check; per‑host alert email.
6. **Educational / Expert dual mode**; first‑run CA explainer; key‑type guidance.
7. **Monitor‑only hosts** + **remote certbot** issuance/renewal.
8. **Network discovery scan** (RFC1918) + hostname guessing (rDNS / TLS CN / NetBIOS) + bulk add.
9. **Per‑root subject DN** inherited by issued certs.
10. Host **edit/rename**; OS type; host delete.
11. Settings grouped into fieldsets; **cipher‑aware key length**; defaults applied to issuance dialogs.
12. **Owner/Environment dropdowns** with editable Settings lists (no JSON).
13. Login/dialog **blur backdrop + elevation shadow**.
14. "Machines" → **"Monitoring"**; panels reordered (Discover → Add → table).
15. Hierarchical **host → port → vhost** monitoring editor + `sni_host` scanner support.
16. Bug fixes: settings key‑length load, scan‑add (machine + monitored port), and
    **migration‑010 `CREATE INDEX IF NOT EXISTS`** (crashed any restart against an existing DB).

---

## 6. Known gaps / planned

- **SAN support** — issued leaf certs are currently CN‑only. Needed: DNS + IP SubjectAltNames so a
  cert is valid for given hostnames/IPs (and for **multi‑IP hosts**).
- **mTLS** — certificate purpose (server / client / both) → Extended Key Usage (`serverAuth`/`clientAuth`).
- **Monitoring table enhancements** — dedicated TLS‑version column, full cipher/protocol enumeration
  in details, and an issues‑only filter.
- **SSH host‑key pinning** — the deployment client currently accepts any host key (lab‑acceptable; pin before wider use).
