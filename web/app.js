const state = {
  token: sessionStorage.getItem("akamana_token") || "",
  user: null,
  /** Public deployment info from /api/v1/branding (title, which factors exist). */
  branding: null,
  /** Which sign-in step is on screen, plus the tokens that step needs. */
  auth: { step: "credentials", mfaToken: null, username: null, resetToken: null },
  /** Cached /api/v1/mfa/status for the Profile > security section. */
  security: null,
  mode: localStorage.getItem("akamana_mode") || "standard",
  lang: "en",
  tab: "tls",
  logsTab: "actions",
  currentPage: "certs",
  selected: null,
  selectedRootId: 1,
  collapsedNodes: {},
  applications: [],
  credentials: [],
  selectedHostId: "",
  monHostId: "",
  hostCredentials: [],
  hostApplications: [],
  owners: ["lab-ops", "security", "devops"],
  environments: ["production", "staging", "internal-lab", "development"],
  deployPlatform: "windows",
  roots: [],
  tls: [],
  ssh: [],
  machines: [],
  machineMonitorRows: [],
  selectedMachineMonitorRow: null,
  machineMonitorSettings: null,
  selectedDetail: null,
  tlsDetailCache: {},
  deployGuide: null,
  crypto: {
    tls: { ciphers: [], key_lengths: [256, 2048, 4096], cert_levels: [] },
    ssh: { ciphers: [], key_lengths: [256, 2048, 4096] },
  },
};

const LOG_TABLE_CONFIG = {
  actions: {
    outputId: "action-logs-output",
    columns: ["id", "actor", "action", "target_type", "target_id", "details", "created_at"],
  },
  access: {
    outputId: "access-logs-output",
    columns: ["id", "actor", "source_ip", "method", "path", "status_code", "created_at"],
  },
  security: {
    outputId: "security-logs-output",
    columns: ["id", "event_type", "severity", "source_ip", "details", "created_at"],
  },
};

const OS_INFO = {
  windows: {
    title: "Windows",
    desc: "Install into Trusted Root Certification Authorities.",
    steps: [
      "Download the root certificate file (.cer).",
      "Open the file and click Install Certificate.",
      "Choose Local Machine, then Trusted Root Certification Authorities.",
      "Confirm and close.",
    ],
  },
  macos: {
    title: "macOS",
    desc: "Install into Keychain Access and set certificate trust.",
    steps: [
      "Download the root certificate file (.pem).",
      "Open Keychain Access and import the certificate into System keychain.",
      "Open the certificate and set Trust to Always Trust.",
      "Close and authenticate.",
    ],
  },
  linux_debian: {
    title: "Linux (Debian / Ubuntu)",
    desc: "Add the CA to the system trust store with update-ca-certificates.",
    downloadPlatform: "linux",
    steps: [
      "Download the root certificate (.crt / PEM).",
      "Copy it to /usr/local/share/ca-certificates/ (filename must end in .crt).",
      "Run sudo update-ca-certificates.",
      "Restart services using TLS if needed.",
    ],
    command: (base, rootId) =>
      `sudo sh -c 'curl -fsSk -o /usr/local/share/ca-certificates/akamana-root.crt "${base}/api/v1/certificates/root/download/linux?root_id=${rootId}" && update-ca-certificates'`,
  },
  linux_rhel: {
    title: "Linux (RHEL / Fedora / CentOS)",
    desc: "Add the CA to the system trust store with update-ca-trust.",
    downloadPlatform: "linux",
    steps: [
      "Download the root certificate (.crt / PEM).",
      "Copy it to /etc/pki/ca-trust/source/anchors/.",
      "Run sudo update-ca-trust extract.",
      "Restart services using TLS if needed.",
    ],
    command: (base, rootId) =>
      `sudo sh -c 'curl -fsSk -o /etc/pki/ca-trust/source/anchors/akamana-root.crt "${base}/api/v1/certificates/root/download/linux?root_id=${rootId}" && update-ca-trust extract'`,
  },
  ios: {
    title: "iOS",
    desc: "Install profile and enable full trust.",
    steps: [
      "Download the root certificate file (.cer).",
      "Open the downloaded profile and install it.",
      "Go to Settings > General > About > Certificate Trust Settings.",
      "Enable full trust for the root certificate.",
    ],
  },
  android: {
    title: "Android",
    desc: "Install CA certificate from security settings.",
    steps: [
      "Download the root certificate file (.crt).",
      "Open Settings > Security > Encryption and credentials.",
      "Install a certificate > CA certificate.",
      "Select downloaded file and confirm.",
    ],
  },
};

const FIELD_HELP = {
  id: "Unique identifier of this record in Akamana.",
  common_name: "Main name that this certificate identifies (for example a DNS name).",
  cert_level: "Certificate role in the chain: root, intermediate, or leaf/service certificate.",
  organization: "Organization that owns and manages this certificate authority.",
  serial_hex: "Certificate serial number used for audits and revocation checks.",
  cipher: "Cryptographic algorithm used to generate keys and sign the certificate.",
  key_length: "Only adjustable for RSA (2048/3072/4096; bigger = stronger but slower). Ed25519 and ECDSA P-256 have a fixed size set by the algorithm, so there is nothing to choose.",
  valid_from: "Date and time when the certificate becomes valid.",
  valid_to: "Date and time when the certificate expires.",
  not_before: "Start of validity period.",
  not_after: "End of validity period.",
  is_revoked: "Whether the certificate has been invalidated before expiration.",
  revoked_reason: "Reason for revocation, if revoked.",
  machine_name: "Server or machine associated with this certificate.",
  ip_address: "Network IP address tied to the machine or service.",
  owner: "Owner or team responsible for operating and renewing this certificate.",
  environment: "Deployment environment where this certificate will be used.",
  valid_days: "Certificate validity duration in days before expiration.",
  publish_private_key: "If enabled, private key export can be downloaded from Akamana.",
  allow_private_key_export: "Whether Akamana allows downloading the private key.",
  cert_pem: "Public certificate content in PEM format.",
  private_key_pem: "Private key in PEM format. Keep this secret.",
  public_key: "Public key content used by peers to verify identity.",
  private_key: "Private SSH key. Keep this secret.",
  fingerprint: "Short identity hash of an SSH public key.",
  ssh_username: "User account associated with the SSH key.",
  parent_cert_id: "Parent certificate that signed this certificate.",
  usages: "Permitted operations for this certificate (for example TLS server auth).",
};

const DEPLOY_PROFILES = {
  nginx: {
    label: "Nginx",
    steps: [
      "Place certificate files in a secure folder readable by Nginx.",
      "Set `ssl_certificate` to the full chain file and `ssl_certificate_key` to the private key.",
      "Run `nginx -t` to validate configuration.",
      "Reload Nginx with `systemctl reload nginx`.",
    ],
  },
  nginx_docker_container: {
    label: "Nginx (Docker container)",
    steps: [
      "Copy cert/key files into the running Nginx Docker container.",
      "Apply secure WebSocket config with Upgrade/Connection headers.",
      "Validate config with `docker exec <container> nginx -t`.",
      "Reload Nginx inside the container.",
    ],
  },
  nginx_podman_container: {
    label: "Nginx (Podman container)",
    steps: [
      "Copy cert/key files into the running Nginx Podman container.",
      "Apply secure WebSocket config with Upgrade/Connection headers.",
      "Validate config with `podman exec <container> nginx -t`.",
      "Reload Nginx inside the container.",
    ],
  },
  apache: {
    label: "Apache HTTPD",
    steps: [
      "Copy certificate files to a secure path.",
      "Set `SSLCertificateFile` to full chain and `SSLCertificateKeyFile` to private key.",
      "If required, set `SSLCertificateChainFile` to intermediate certificate.",
      "Validate and reload Apache (`apachectl configtest`, then restart/reload).",
    ],
  },
  iis: {
    label: "IIS (Windows)",
    steps: [
      "Import certificate/private key as a PFX in the Local Machine certificate store.",
      "Bind HTTPS in IIS Manager to the imported certificate.",
      "If intermediate CA is missing, import it in Intermediate Certification Authorities store.",
      "Restart the site or IIS service.",
    ],
  },
  haproxy: {
    label: "HAProxy",
    steps: [
      "Combine leaf certificate, intermediate certificate(s), and private key into one PEM bundle.",
      "Reference the bundle in `bind ... ssl crt /path/to/bundle.pem`.",
      "Check config with `haproxy -c -f /etc/haproxy/haproxy.cfg`.",
      "Reload HAProxy.",
    ],
  },
  kubernetes: {
    label: "Kubernetes Ingress",
    steps: [
      "Create/update a TLS secret with leaf cert and private key.",
      "Ensure certificate chain includes intermediate certificate(s).",
      "Reference the secret from Ingress `spec.tls`.",
      "Apply manifests and verify ingress controller logs.",
    ],
  },
  custom: {
    label: "Other / Custom app",
    steps: [
      "Check whether the app expects file upload, file paths, or pasted PEM text.",
      "Use leaf certificate plus intermediate certificate(s) as chain when required.",
      "Provide private key only to trusted hosts and operators.",
      "Restart application/service and verify TLS handshake from a client.",
    ],
  },
};

const CIPHER_COMPATIBILITY_CONFIG = [
  { selectId: "org-root-cipher", hintId: "org-root-cipher-compat", domain: "tls" },
  { selectId: "org-int-cipher", hintId: "org-int-cipher-compat", domain: "tls" },
  { selectId: "cf-tls-cipher", hintId: "cf-tls-cipher-compat", domain: "tls" },
  { selectId: "cf-ssh-cipher", hintId: "cf-ssh-cipher-compat", domain: "ssh" },
  { selectId: "im-tls-cipher", hintId: "im-tls-cipher-compat", domain: "tls" },
  { selectId: "default_tls_cipher", hintId: "default-tls-cipher-compat", domain: "tls" },
  { selectId: "default_ssh_cipher", hintId: "default-ssh-cipher-compat", domain: "ssh" },
];

const KEY_LENGTH_PAIRS = [
  ["cf-tls-cipher", "cf-tls-key-length"],
  ["cf-ssh-cipher", "cf-ssh-key-length"],
  ["org-root-cipher", "org-root-key-length"],
  ["org-int-cipher", "org-int-key-length"],
  ["im-tls-cipher", "im-tls-key-length"],
  ["default_tls_cipher", "default_tls_key_length"],
  ["default_ssh_cipher", "default_ssh_key_length"],
];

function keyLengthOptionsForCipher(cipher) {
  const c = String(cipher || "").toLowerCase();
  if (c === "rsa") {
    return { options: [["2048", "2048"], ["3072", "3072 (recommended)"], ["4096", "4096 (extra margin)"]], def: "3072" };
  }
  if (c === "ecdsa_p256" || c === "ecdsa") {
    return { options: [["256", "P-256 curve (fixed)"]], def: "256" };
  }
  // ed25519 and anything else: key size is fixed by the algorithm.
  return { options: [["256", "256 — fixed by Ed25519"]], def: "256" };
}

function applyKeyLengthOptions() {
  KEY_LENGTH_PAIRS.forEach(([cipherId, lenId]) => {
    const cipherSel = el(cipherId);
    const lenSel = el(lenId);
    if (!cipherSel || !lenSel) return;
    const spec = keyLengthOptionsForCipher(cipherSel.value);
    const prev = lenSel.value;
    lenSel.innerHTML = "";
    spec.options.forEach(([value, label]) => {
      const o = document.createElement("option");
      o.value = value;
      o.textContent = label;
      lenSel.appendChild(o);
    });
    lenSel.value = spec.options.some(([v]) => v === prev) ? prev : spec.def;
  });
}

function el(id) {
  return document.getElementById(id);
}

function pretty(v) {
  return JSON.stringify(v, null, 2);
}

function asItems(v) {
  if (Array.isArray(v)) return v;
  if (v && Array.isArray(v.items)) return v.items;
  return [];
}

function humanizeKey(key) {
  return String(key || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") {
    if (/^\d{4}-\d{2}-\d{2}T/.test(value) || /^\d{4}-\d{2}-\d{2} /.test(value)) {
      const d = new Date(value);
      if (!Number.isNaN(d.getTime())) return d.toLocaleString();
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ");
  return JSON.stringify(value, null, 2);
}

function openInfoModal(field, labelOverride) {
  const name = labelOverride || humanizeKey(field);
  const explanation = FIELD_HELP[field] || "No extra explanation is available yet for this field.";
  el("info-title").textContent = name;
  el("info-body").textContent = explanation;
  el("info-modal").showModal();
}

function bindInlineInfoIcons() {
  document.querySelectorAll("[data-info-field]").forEach((btn) => {
    if (btn.dataset.infoBound === "1") return;
    btn.dataset.infoBound = "1";
    btn.addEventListener("click", () => {
      const field = btn.dataset.infoField || "";
      const label = btn.dataset.infoLabel || "";
      openInfoModal(field, label || undefined);
    });
  });
}

// Confirms a copy on the button itself. Writing only to a distant status
// line means the operator clicks, sees nothing move, and clicks again.
function flashCopyFeedback(btn, ok) {
  if (!btn) return;
  if (btn.dataset.copyRestoring === "1") return;
  const prev = btn.textContent;
  btn.dataset.copyRestoring = "1";
  btn.textContent = ok ? "Copied!" : "Copy failed";
  btn.classList.add(ok ? "copy-ok" : "copy-failed");
  setTimeout(() => {
    btn.textContent = prev;
    btn.classList.remove("copy-ok", "copy-failed");
    delete btn.dataset.copyRestoring;
  }, 1500);
}

async function copyTextToClipboard(text) {
  const value = String(text || "");
  if (!value) return false;
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.setAttribute("readonly", "readonly");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

const SECRET_FIELDS = new Set(["private_key_pem", "private_key", "ssh_private_key"]);

function buildSecretValue(secret) {
  const wrap = document.createElement("div");
  wrap.className = "secret-value";
  const masked = document.createElement("span");
  masked.className = "value-text secret-masked";
  masked.textContent = "••••••••••••••••••••••••";
  const revealed = document.createElement("pre");
  revealed.className = "value-text secret-revealed";
  revealed.textContent = secret;
  revealed.hidden = true;
  const controls = document.createElement("div");
  controls.className = "row-actions";
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.textContent = "Show";
  toggle.addEventListener("click", () => {
    const show = revealed.hidden;
    revealed.hidden = !show;
    masked.hidden = show;
    toggle.textContent = show ? "Hide" : "Show";
  });
  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy";
  copy.addEventListener("click", async () => {
    const ok = await copyTextToClipboard(secret);
    const prev = copy.textContent;
    copy.textContent = ok ? "Copied!" : "Copy failed";
    setTimeout(() => { copy.textContent = prev; }, 1200);
  });
  controls.append(toggle, copy);
  wrap.append(masked, revealed, controls);
  return wrap;
}

function renderObjectAsTable(target, value, preferredOrder = []) {
  target.innerHTML = "";
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = formatValue(value);
    target.appendChild(p);
    return;
  }
  const table = document.createElement("table");
  table.className = "kv-table";
  const tbody = document.createElement("tbody");
  const keys = Object.keys(value);
  keys.sort((a, b) => {
    const ai = preferredOrder.indexOf(a);
    const bi = preferredOrder.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
  keys.forEach((key) => {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    const labelWrap = document.createElement("span");
    labelWrap.className = "field-label";
    const label = document.createElement("span");
    label.textContent = humanizeKey(key);
    const info = document.createElement("button");
    info.type = "button";
    info.className = "info-icon";
    info.textContent = "i";
    info.title = "What does this mean?";
    info.addEventListener("click", () => openInfoModal(key, humanizeKey(key)));
    labelWrap.append(label, info);
    th.appendChild(labelWrap);
    const td = document.createElement("td");
    if (SECRET_FIELDS.has(key) && typeof value[key] === "string" && value[key].trim()) {
      td.appendChild(buildSecretValue(value[key]));
    } else {
      const v = document.createElement("div");
      v.className = "value-text";
      v.textContent = formatValue(value[key]);
      td.appendChild(v);
    }
    tr.append(th, td);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  target.appendChild(table);
}

function renderCollection(target, value) {
  target.innerHTML = "";
  const list = asItems(value);
  if (!list.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No data.";
    target.appendChild(p);
    return;
  }
  list.forEach((item, idx) => {
    const card = document.createElement("article");
    card.className = "log-card";
    const title = document.createElement("h4");
    title.textContent = `Record ${idx + 1}`;
    const holder = document.createElement("div");
    holder.className = "kv-output";
    renderObjectAsTable(holder, item);
    card.append(title, holder);
    target.appendChild(card);
  });
}

function renderLogTable(target, value, columns) {
  target.innerHTML = "";
  const rows = asItems(value);
  if (!rows.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No data.";
    target.appendChild(p);
    return;
  }

  const table = document.createElement("table");
  table.className = "logs-table";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  columns.forEach((column) => {
    const th = document.createElement("th");
    th.textContent = humanizeKey(column);
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);

  const tbody = document.createElement("tbody");
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    columns.forEach((column) => {
      const td = document.createElement("td");
      const valueCell = row?.[column];
      if (column === "details" && valueCell && typeof valueCell === "object") {
        const pre = document.createElement("pre");
        pre.className = "log-json";
        pre.textContent = JSON.stringify(valueCell, null, 2);
        td.appendChild(pre);
      } else {
        td.textContent = formatValue(valueCell);
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });

  table.append(thead, tbody);
  target.appendChild(table);
}

function setLogsTab(tab) {
  state.logsTab = tab;
  document.querySelectorAll("[data-log-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.logTab === tab);
  });
  ["actions", "access", "security"].forEach((name) => {
    const panel = el(`logs-panel-${name}`);
    if (panel) panel.hidden = name !== tab;
  });
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { ...opts, headers });
  const txt = await res.text();
  let body = txt;
  try {
    body = JSON.parse(txt);
  } catch (_) {}
  if (!res.ok) {
    // Prefer the API's human-readable `error` field; fall back to plain text.
    const msg =
      body && typeof body === "object" && typeof body.error === "string"
        ? body.error
        : typeof body === "string" && body.trim()
        ? body
        : `Request failed (${res.status})`;
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function authUi() {
  const auth = Boolean(state.token);
  setMainMenuOpen(false);
  el("workspace").hidden = !auth;
  el("public-root").hidden = auth;
  el("logout-btn").hidden = !auth;
  el("login-open").hidden = auth;
  document.querySelectorAll(".nav-item").forEach((n) => (n.hidden = !auth));
  if (auth) showPage("certs");
}

function showPage(page) {
  state.currentPage = page;
  document.querySelectorAll(".page").forEach((p) => (p.hidden = true));
  const target = el(`page-${page}`);
  if (target) target.hidden = false;
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.page === page));
  setMainMenuOpen(false);
}

function setLang(lang) {
  state.lang = lang;
}

function applyMode() {
  document.body.classList.toggle("mode-expert", state.mode === "expert");
  const btn = el("mode-toggle");
  if (btn) btn.textContent = state.mode === "expert" ? "Expert mode" : "Standard mode";
}

function toggleMode() {
  state.mode = state.mode === "expert" ? "standard" : "expert";
  localStorage.setItem("akamana_mode", state.mode);
  applyMode();
}

function renderFirstRun() {
  const panel = el("certs-first-run");
  if (panel) panel.hidden = state.roots.length > 0;
}

function setMainMenuOpen(open) {
  const panel = el("main-menu");
  if (!panel) return;
  if (open) {
    panel.hidden = false;
    requestAnimationFrame(() => panel.classList.add("open"));
    return;
  }
  if (panel.hidden) return;
  panel.classList.remove("open");
  const hideAfterTransition = () => {
    panel.hidden = true;
    panel.removeEventListener("transitionend", hideAfterTransition);
  };
  panel.addEventListener("transitionend", hideAfterTransition);
}

async function loadRoots() {
  state.roots = await api("/api/v1/certificates/root");
  if (state.roots.length) {
    state.selectedRootId = Number(state.roots[0].id);
  }
  fillRootSelects();
  syncRootSelectValues();
  renderDeploy(false);
  renderDeploy(true);
}

function fillRootSelects() {
  const selects = ["public-root-select", "private-root-select", "org-root-select", "cf-root-id", "im-root-id"];
  selects.forEach((id) => {
    const node = el(id);
    if (!node) return;
    node.innerHTML = "";
    state.roots.forEach((r) => {
      const option = document.createElement("option");
      option.value = String(r.id);
      option.textContent = `${r.organization} - ${r.common_name}`;
      node.appendChild(option);
    });
    if (state.roots.length) node.value = String(state.selectedRootId);
  });
}

function selectedRoot() {
  return state.roots.find((r) => Number(r.id) === Number(state.selectedRootId));
}

function syncRootSelectValues() {
  ["public-root-select", "private-root-select", "org-root-select", "cf-root-id", "im-root-id"].forEach((id) => {
    const n = el(id);
    if (n && state.roots.length) n.value = String(state.selectedRootId);
  });
}

// Light wireframe OS glyphs (stroke = currentColor, no fill) for the deploy tabs.
function osIcon(platform) {
  const key = platform.startsWith("linux") ? "linux" : platform;
  const open = '<svg class="os-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">';
  const dot = (x, y) => `<circle cx="${x}" cy="${y}" r=".7" fill="currentColor" stroke="none"/>`;
  const paths = {
    windows:
      '<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/>',
    macos:
      '<path d="M16.2 12.7c0 3 2.4 3.9 2.4 3.9-.2.6-.9 2-1.9 3-.8.8-1.6 1.5-2.7 1.5-1 0-1.4-.6-2.6-.6-1.3 0-1.7.6-2.7.6-1 0-1.8-.8-2.6-1.6C1.7 18 1.5 13.4 4.4 12c1-.5 2-.4 2.9-.4 1.1 0 1.9.6 2.7.6.8 0 1.9-.7 3.2-.6.9 0 2.4.3 3 1.5-2.6 1.5-2.2 4.2 0 5.6z"/><path d="M13.4 5.9c.6-.7 1-1.7.9-2.7-.9.1-1.9.6-2.5 1.3-.6.7-1 1.7-.9 2.6 1 .1 1.9-.5 2.5-1.2z"/>',
    ios:
      '<rect x="7" y="2" width="10" height="20" rx="2.2"/><line x1="10.3" y1="18.7" x2="13.7" y2="18.7"/>',
    android:
      '<path d="M5 11.5a7 7 0 0 1 14 0V18a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1z"/><line x1="8.8" y1="7.6" x2="7.4" y2="5.6"/><line x1="15.2" y1="7.6" x2="16.6" y2="5.6"/>' +
      dot(9.5, 12) + dot(14.5, 12) +
      '<line x1="2.5" y1="12" x2="2.5" y2="16"/><line x1="21.5" y1="12" x2="21.5" y2="16"/>',
    linux:
      '<path d="M12 2.6c2 0 3.3 1.7 3.3 4 0 1.4.4 2.1 1.2 3.3.9 1.3 2.1 2.8 2.1 5.5 0 2.3-1.1 3.7-2.3 4.4.2.6.3 1.2.3 1.7H7.4c0-.5.1-1.1.3-1.7-1.2-.7-2.3-2.1-2.3-4.4 0-2.7 1.2-4.2 2.1-5.5.8-1.2 1.2-1.9 1.2-3.3 0-2.3 1.3-4 3.3-4z"/>' +
      dot(10.4, 8) + dot(13.6, 8) +
      '<path d="M10.7 9.8 12 11l1.3-1.2"/>',
  };
  return open + (paths[key] || paths.linux) + "</svg>";
}

function renderDeploy(privateMode) {
  const rootSelect = el(privateMode ? "private-root-select" : "public-root-select");
  const meta = el(privateMode ? "private-root-meta" : "public-root-meta");
  const tabs = el(privateMode ? "private-os-tabs" : "public-os-tabs");
  const title = el(privateMode ? "private-os-title" : "public-os-title");
  const desc = el(privateMode ? "private-os-desc" : "public-os-desc");
  const steps = el(privateMode ? "private-os-steps" : "public-os-steps");
  const dl = el(privateMode ? "private-download-link" : "public-download-link");

  if (!state.roots.length) {
    if (!privateMode) {
      el("public-empty-msg").hidden = false;
      el("public-deploy-content").hidden = true;
    }
    if (meta) meta.textContent = "No Root CA available.";
    return;
  }

  if (!privateMode) {
    el("public-empty-msg").hidden = true;
    el("public-deploy-content").hidden = false;
  }
  if (rootSelect) rootSelect.value = String(state.selectedRootId);

  const root = selectedRoot();
  meta.textContent = root
    ? `Organization: ${root.organization} | Valid: ${new Date(root.not_before).toLocaleDateString()} -> ${new Date(root.not_after).toLocaleDateString()}`
    : "";

  tabs.innerHTML = "";
  Object.keys(OS_INFO).forEach((platform) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "os-tab";
    if (platform === state.deployPlatform) b.classList.add("active");
    b.innerHTML = `${osIcon(platform)}<span>${OS_INFO[platform].title}</span>`;
    b.addEventListener("click", () => {
      state.deployPlatform = platform;
      renderDeploy(privateMode);
    });
    tabs.appendChild(b);
  });

  const cfg = OS_INFO[state.deployPlatform];
  title.textContent = cfg.title;
  desc.textContent = cfg.desc;
  steps.innerHTML = "";
  cfg.steps.forEach((s) => {
    const li = document.createElement("li");
    li.textContent = s;
    steps.appendChild(li);
  });
  const dlPlatform = cfg.downloadPlatform || state.deployPlatform;
  dl.href = `/api/v1/certificates/root/download/${dlPlatform}?root_id=${encodeURIComponent(state.selectedRootId)}`;

  const cmdWrap = el(privateMode ? "private-os-command-wrap" : "public-os-command-wrap");
  const cmdPre = el(privateMode ? "private-os-command" : "public-os-command");
  if (cmdWrap && cmdPre) {
    if (typeof cfg.command === "function") {
      const base = (state.defaults && state.defaults.public_base_url) || window.location.origin;
      cmdPre.textContent = cfg.command(base.replace(/\/+$/, ""), state.selectedRootId);
      cmdWrap.hidden = false;
    } else {
      cmdWrap.hidden = true;
    }
  }
}

// ---------------------------------------------------------------------------
// Sign-in
//
// One dialog, several steps: credentials -> (second factor | forced enrollment)
// -> recovery codes, plus the forgot-password and reset-password steps. All the
// step bookkeeping lives in `state.auth`; `showAuthStep` is the only thing that
// decides what is on screen.
// ---------------------------------------------------------------------------

const APP_NAME = () => (state.branding && state.branding.app_title) || "Akamana";

function setAuthAlert(message) {
  const box = el("auth-alert");
  box.textContent = message || "";
  box.hidden = !message;
  if (message) el("auth-notice").hidden = true;
}

function setAuthNotice(message) {
  const box = el("auth-notice");
  box.textContent = message || "";
  box.hidden = !message;
  if (message) el("auth-alert").hidden = true;
}

function clearAuthMessages() {
  setAuthAlert("");
  setAuthNotice("");
  document.querySelectorAll("#login-modal .auth-field-error").forEach((n) => {
    n.textContent = "";
    n.hidden = true;
  });
  document.querySelectorAll("#login-modal input.is-invalid").forEach((n) => n.classList.remove("is-invalid"));
}

/** Attaches an error to one field so the user knows which box to fix. */
function setFieldError(inputId, message) {
  const input = el(inputId);
  const box = el(`${inputId}-error`);
  if (input) input.classList.toggle("is-invalid", Boolean(message));
  if (box) {
    box.textContent = message || "";
    box.hidden = !message;
  }
}

function showAuthStep(step) {
  clearAuthMessages();
  state.auth.step = step;
  document.querySelectorAll("#login-modal .auth-step").forEach((node) => {
    node.hidden = node.dataset.step !== step;
  });
  const subtitles = {
    credentials: "Sign in to manage keys and certificates",
    mfa: "Two-factor authentication",
    enroll: "Set up two-factor authentication",
    codes: "Save your recovery codes",
    forgot: "Reset your password",
    reset: "Choose a new password",
  };
  el("auth-subtitle").textContent = subtitles[step] || subtitles.credentials;
  // Deferred, because `showModal()` focuses the dialog's first focusable child
  // (the close button) and would otherwise win. A timer rather than
  // requestAnimationFrame: rAF doesn't fire in a tab that isn't compositing.
  const first = document.querySelector(`#login-modal .auth-step[data-step="${step}"] input`);
  if (first) setTimeout(() => first.focus(), 0);
}

/** Swaps a button into its loading state and blocks double submits. */
function setBusy(button, busy) {
  if (!button) return;
  button.classList.toggle("is-busy", busy);
  button.disabled = busy;
  const label = button.querySelector(".auth-btn-label");
  if (label) label.textContent = busy ? "Working…" : button.dataset.label || label.textContent;
}

/**
 * Turns a fetch/API failure into something a person can act on. `context`
 * distinguishes the steps that share status codes — a 401 on the password step
 * means "wrong password", the same 401 on the code step means "wrong code".
 */
function friendlyAuthError(err, context) {
  if (!err) return "Something went wrong. Please try again.";
  // fetch() rejects with a TypeError (no status) when the server is unreachable.
  if (err.status === undefined) {
    return `Can't reach ${APP_NAME()}. Check your connection and try again.`;
  }
  if (err.status === 429) {
    return err.message || "Too many attempts. Please wait a few minutes and try again.";
  }
  if (err.status === 401 || err.status === 403) {
    // The server can't tell a wrong code from an expired challenge apart in its
    // reply, so name both possibilities.
    if (context === "mfa") {
      return "That code wasn't accepted. Codes change every 30 seconds — try the current one, or start over if this attempt has been sitting for a while.";
    }
    if (context === "passkey") return "That passkey wasn't accepted. Try again, or sign in with your password.";
    return "Incorrect username or password.";
  }
  if (err.status === 400) {
    // The API's validation messages are already written for humans.
    return err.message || "Please check the details you entered.";
  }
  // 422 is axum's request-body deserialization failure — a bug on our side, not
  // something the user can act on. Don't paste the parser's output at them.
  if (err.status === 422 || /Failed to deserialize/i.test(err.message || "")) {
    return "Something went wrong sending that request. Please reload the page and try again.";
  }
  if (err.status >= 500) {
    return `${APP_NAME()} had a problem completing that. Please try again shortly.`;
  }
  return err.message || "Sign-in failed. Please try again.";
}

/** Client-side checks, so obvious mistakes never cost a round trip. */
function validateCredentials(username, password) {
  let ok = true;
  if (!username.trim()) {
    setFieldError("login-user", "Enter your username.");
    ok = false;
  }
  if (!password) {
    setFieldError("login-pass", "Enter your password.");
    ok = false;
  } else if (password.length < 12) {
    setFieldError("login-pass", "Passwords on this server are at least 12 characters.");
    ok = false;
  }
  return ok;
}

function applySession(out) {
  state.token = out.access_token;
  state.user = { username: out.username, role: out.role };
  sessionStorage.setItem("akamana_token", out.access_token);
}

/** Finishes a successful sign-in: close the dialog and load the workspace. */
async function completeLogin() {
  state.auth.mfaToken = null;
  el("login-modal").close();
  authUi();
  await refreshAll();
}

function openLogin(step = "credentials") {
  const modal = el("login-modal");
  if (!modal.open) modal.showModal();
  showAuthStep(step);
}

async function submitLogin(button) {
  const username = el("login-user").value;
  const password = el("login-pass").value;
  clearAuthMessages();
  if (!validateCredentials(username, password)) return;

  setBusy(button, true);
  try {
    const out = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: username.trim(), password }),
    });

    if (out.mfa_required) {
      state.auth.mfaToken = out.mfa_token;
      state.auth.username = out.username;
      el("login-pass").value = "";
      if (out.mfa_setup_required) {
        await startForcedEnrollment();
      } else {
        el("mfa-username").textContent = out.username;
        el("mfa-recovery-hint").hidden = !(out.methods || []).includes("recovery");
        el("mfa-code").value = "";
        showAuthStep("mfa");
      }
      return;
    }

    applySession(out);
    el("login-pass").value = "";
    await completeLogin();
  } catch (err) {
    setAuthAlert(friendlyAuthError(err, "credentials"));
  } finally {
    setBusy(button, false);
  }
}

async function submitMfa(button) {
  const code = el("mfa-code").value.trim();
  clearAuthMessages();
  if (!code) {
    setFieldError("mfa-code", "Enter the code from your authenticator app.");
    return;
  }
  setBusy(button, true);
  try {
    const out = await api("/api/v1/auth/login/mfa", {
      method: "POST",
      body: JSON.stringify({ mfa_token: state.auth.mfaToken, code }),
    });
    applySession(out);
    await completeLogin();
  } catch (err) {
    setAuthAlert(friendlyAuthError(err, "mfa"));
    el("mfa-code").select();
  } finally {
    setBusy(button, false);
  }
}

/** REQUIRE_MFA is on and this account has no factor yet: enroll before entry. */
async function startForcedEnrollment() {
  try {
    const setup = await api("/api/v1/auth/login/mfa/enroll/start", {
      method: "POST",
      body: JSON.stringify({ mfa_token: state.auth.mfaToken }),
    });
    el("enroll-qr").src = setup.qr_data_url;
    el("enroll-secret").textContent = setup.secret;
    el("enroll-code").value = "";
    showAuthStep("enroll");
  } catch (err) {
    showAuthStep("credentials");
    setAuthAlert(friendlyAuthError(err, "credentials"));
  }
}

async function submitEnrollment(button) {
  const code = el("enroll-code").value.trim();
  clearAuthMessages();
  if (!code) {
    setFieldError("enroll-code", "Enter the 6-digit code your app is showing.");
    return;
  }
  setBusy(button, true);
  try {
    const out = await api("/api/v1/auth/login/mfa/enroll/finish", {
      method: "POST",
      body: JSON.stringify({ mfa_token: state.auth.mfaToken, code }),
    });
    applySession(out);
    // Hold the session until the recovery codes have been acknowledged.
    renderRecoveryCodes(el("auth-recovery-codes"), out.recovery_codes || []);
    showAuthStep("codes");
  } catch (err) {
    setAuthAlert(friendlyAuthError(err, "mfa"));
    el("enroll-code").select();
  } finally {
    setBusy(button, false);
  }
}

async function submitForgot(button) {
  const identifier = el("forgot-identifier").value.trim();
  clearAuthMessages();
  if (!identifier) {
    setFieldError("forgot-identifier", "Enter your username or email address.");
    return;
  }
  setBusy(button, true);
  try {
    const out = await api("/api/v1/auth/password-reset/request", {
      method: "POST",
      body: JSON.stringify({ identifier }),
    });
    // Deliberately the same answer whether or not the account exists.
    setAuthNotice(out.message || "If that account exists, a reset link is on its way.");
    el("forgot-identifier").value = "";
  } catch (err) {
    setAuthAlert(friendlyAuthError(err, "forgot"));
  } finally {
    setBusy(button, false);
  }
}

/** 0–4 score driving the meter on the reset step. Guidance, not enforcement. */
function passwordScore(value) {
  if (!value) return 0;
  let score = 0;
  if (value.length >= 12) score += 1;
  if (value.length >= 16) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value)) score += 1;
  return Math.min(score, 4);
}

function updatePasswordMeter() {
  const value = el("reset-pass").value;
  const score = passwordScore(value);
  const meter = el("reset-pass").closest(".auth-field").querySelector(".auth-meter");
  meter.className = `auth-meter level-${score}`;
  el("reset-meter-bar").style.width = `${(score / 4) * 100}%`;
  const labels = [
    "At least 12 characters.",
    "Weak — add length.",
    "Fair — a longer passphrase is stronger.",
    "Good.",
    "Strong.",
  ];
  el("reset-meter-text").textContent = value.length && value.length < 12
    ? `${12 - value.length} more character${12 - value.length === 1 ? "" : "s"} needed.`
    : labels[score];
}

async function submitReset(button) {
  const pass = el("reset-pass").value;
  const repeat = el("reset-pass2").value;
  clearAuthMessages();
  if (pass.length < 12) {
    setFieldError("reset-pass2", "");
    setAuthAlert("Your new password must be at least 12 characters.");
    return;
  }
  if (pass !== repeat) {
    setFieldError("reset-pass2", "The two passwords don't match.");
    return;
  }
  setBusy(button, true);
  try {
    const out = await api("/api/v1/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify({ token: state.auth.resetToken, new_password: pass }),
    });
    state.auth.resetToken = null;
    el("reset-pass").value = "";
    el("reset-pass2").value = "";
    showAuthStep("credentials");
    setAuthNotice(out.message || "Your password has been changed. You can sign in now.");
  } catch (err) {
    setAuthAlert(friendlyAuthError(err, "reset"));
  } finally {
    setBusy(button, false);
  }
}

function renderRecoveryCodes(target, codes) {
  target.innerHTML = "";
  codes.forEach((code) => {
    const li = document.createElement("li");
    li.textContent = code;
    target.appendChild(li);
  });
  target.dataset.codes = codes.join("\n");
}

async function copyRecoveryCodes(listId, statusFn) {
  const text = el(listId).dataset.codes || "";
  try {
    await navigator.clipboard.writeText(text);
    statusFn("Recovery codes copied to the clipboard.");
  } catch (_) {
    statusFn("Copy failed — select the codes and copy them manually.");
  }
}

// ---- WebAuthn / passkeys -------------------------------------------------
// The server speaks base64url (that's how webauthn-rs serialises credential
// ids and challenges); the browser API speaks ArrayBuffer. These four helpers
// are the whole translation layer.

function b64urlToBuf(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreationOptions(response) {
  const pk = response.publicKey;
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.user.id = b64urlToBuf(pk.user.id);
  if (pk.excludeCredentials) {
    pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
  }
  return pk;
}

function decodeRequestOptions(response) {
  const pk = response.publicKey;
  pk.challenge = b64urlToBuf(pk.challenge);
  if (pk.allowCredentials) {
    pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
  }
  return pk;
}

function encodeAttestation(credential) {
  return {
    id: credential.id,
    rawId: bufToB64url(credential.rawId),
    type: credential.type,
    extensions: credential.getClientExtensionResults(),
    response: {
      attestationObject: bufToB64url(credential.response.attestationObject),
      clientDataJSON: bufToB64url(credential.response.clientDataJSON),
    },
  };
}

function encodeAssertion(credential) {
  return {
    id: credential.id,
    rawId: bufToB64url(credential.rawId),
    type: credential.type,
    extensions: credential.getClientExtensionResults(),
    response: {
      authenticatorData: bufToB64url(credential.response.authenticatorData),
      clientDataJSON: bufToB64url(credential.response.clientDataJSON),
      signature: bufToB64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufToB64url(credential.response.userHandle) : null,
    },
  };
}

function passkeysAvailable() {
  return Boolean(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
}

async function loginWithPasskey(button) {
  clearAuthMessages();
  const username = el("login-user").value.trim();
  if (!username) {
    setFieldError("login-user", "Enter your username first, then use your passkey.");
    return;
  }
  if (!passkeysAvailable()) {
    setAuthAlert("This browser can't use passkeys here. Passkeys need an HTTPS connection.");
    return;
  }

  setBusy(button, true);
  try {
    const start = await api("/api/v1/auth/passkey/login/start", {
      method: "POST",
      body: JSON.stringify({ username }),
    });
    const assertion = await navigator.credentials.get({
      publicKey: decodeRequestOptions(start.options),
    });
    if (!assertion) throw new Error("No passkey was selected.");

    const out = await api("/api/v1/auth/passkey/login/finish", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: start.challenge_id,
        credential: encodeAssertion(assertion),
      }),
    });
    applySession(out);
    await completeLogin();
  } catch (err) {
    // The browser throws NotAllowedError when the user dismisses the prompt.
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      setAuthAlert("Passkey sign-in was cancelled.");
    } else {
      setAuthAlert(friendlyAuthError(err, "passkey"));
    }
  } finally {
    setBusy(button, false);
  }
}

async function loadBranding() {
  try {
    state.branding = await api("/api/v1/branding");
  } catch (_) {
    state.branding = null;
    return;
  }
  const title = APP_NAME();
  document.title = title;
  el("app-title").textContent = title;
  el("auth-title").textContent = title;
  // Only offer what this deployment actually supports.
  el("passkey-login-row").hidden = !(state.branding.passkeys_enabled && passkeysAvailable());
  el("forgot-open").hidden = !state.branding.password_reset_enabled;
}

function logout() {
  state.token = "";
  state.user = null;
  state.selected = null;
  state.auth = { step: "credentials", mfaToken: null, username: null, resetToken: null };
  sessionStorage.removeItem("akamana_token");
  authUi();
}

async function refreshAll() {
  if (!state.token) return;
  const prevSelected = state.selected;
  await loadRoots().catch(() => {});
  state.crypto = await api("/api/v1/crypto/options").catch(() => state.crypto);
  state.tls = asItems(await api("/api/v1/certificates/tls"));
  state.ssh = asItems(await api("/api/v1/certificates/ssh"));
  state.machines = asItems(await api("/api/v1/machines"));
  fillMachineSelectOptions();
  state.tlsDetailCache = {};
  renderCryptoSelects();
  await loadDefaults().catch(() => {});
  if (prevSelected) {
    if (prevSelected.is_root_row) {
      const root = selectedRoot();
      state.selected = root
        ? {
            id: `root-${root.id}`,
            root_id: Number(root.id),
            is_root_row: true,
            cert_level: "root",
            common_name: root.common_name,
            organization: root.organization,
            not_before: root.not_before,
            not_after: root.not_after,
            is_revoked: Boolean(root.is_revoked),
            revoked_reason: root.revoked_reason || "",
          }
        : null;
    } else {
      const src = state.tab === "tls" ? state.tls : state.ssh;
      state.selected = src.find((x) => x.id === prevSelected.id) || null;
    }
  }
  state.selectedDetail = null;
  renderList();
  renderDetails();
}

function renderCryptoSelects() {
  fillSelect("cf-tls-cipher", state.crypto.tls.ciphers.map((c) => [c.id, c.label]));
  fillSelect("cf-ssh-cipher", state.crypto.ssh.ciphers.map((c) => [c.id, c.label]));
  fillSelect("cf-tls-key-length", state.crypto.tls.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("cf-ssh-key-length", state.crypto.ssh.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("im-tls-cipher", state.crypto.tls.ciphers.map((c) => [c.id, c.label]));
  fillSelect("im-tls-key-length", state.crypto.tls.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("org-root-cipher", state.crypto.tls.ciphers.map((c) => [c.id, c.label]));
  fillSelect("org-root-key-length", state.crypto.tls.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("org-int-cipher", state.crypto.tls.ciphers.map((c) => [c.id, c.label]));
  fillSelect("org-int-key-length", state.crypto.tls.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("default_tls_cipher", state.crypto.tls.ciphers.map((c) => [c.id, c.label]));
  fillSelect("default_ssh_cipher", state.crypto.ssh.ciphers.map((c) => [c.id, c.label]));
  fillSelect("default_tls_key_length", state.crypto.tls.key_lengths.map((n) => [String(n), String(n)]));
  fillSelect("default_ssh_key_length", state.crypto.ssh.key_lengths.map((n) => [String(n), String(n)]));
  applyKeyLengthOptions();
  refreshCipherCompatibilityHints();
}

function fillSelect(id, values) {
  const s = el(id);
  if (!s) return;
  s.innerHTML = "";
  values.forEach(([value, label]) => {
    const o = document.createElement("option");
    o.value = value;
    o.textContent = label;
    s.appendChild(o);
  });
}

function cipherCompatibilityMessage(cipher, domain) {
  const normalized = String(cipher || "").toLowerCase();
  if (normalized === "ed25519") {
    if (domain === "ssh") {
      return "Compatibility: Ed25519 is preferred for modern SSH clients. Very old clients may require RSA.";
    }
    return "Compatibility: Ed25519 is modern and fast, but some older TLS/SSL clients and servers (browsers, appliances, load balancers) may not support it. Use RSA for the widest client and server compatibility.";
  }
  if (normalized === "rsa") {
    if (domain === "ssh") {
      return "Compatibility: RSA has broad SSH client support, including older systems. Prefer Ed25519 when legacy support is not required.";
    }
    return "Compatibility: RSA is broadly supported by browsers, OSes, and TLS appliances, but uses larger keys and more CPU.";
  }
  return `Compatibility: Verify client support for ${cipher || "this cipher"} in your target environment.`;
}

function upsertCipherCompatibilityHint({ selectId, hintId, domain }) {
  const select = el(selectId);
  if (!select) return;
  const formGrid = select.closest(".form-grid");
  if (!formGrid) return;
  let hint = el(hintId);
  if (!hint) {
    hint = document.createElement("p");
    hint.id = hintId;
    hint.className = "hint cipher-compat";
    // Inherit the field's tab visibility so the TLS tab never shows the SSH
    // hint (and vice versa) — the tab handler toggles these classes.
    if (formGrid.classList.contains("tls-only")) hint.classList.add("tls-only");
    if (formGrid.classList.contains("ssh-only")) hint.classList.add("ssh-only");
    hint.hidden = formGrid.hidden;
    formGrid.after(hint);
  }
  hint.textContent = cipherCompatibilityMessage(select.value, domain);
}

function refreshCipherCompatibilityHints() {
  CIPHER_COMPATIBILITY_CONFIG.forEach(upsertCipherCompatibilityHint);
}

function statusDotClass(status) {
  switch (String(status || "").toLowerCase()) {
    case "ok":
      return "dot-ok";
    case "warning":
      return "dot-warn";
    case "expired":
    case "error":
      return "dot-expired";
    default:
      return "dot-unknown";
  }
}

function certExpiryStatus(item) {
  if (item.is_revoked) return { text: "revoked", cls: "st-revoked" };
  const end = item.not_after || item.valid_to;
  if (!end) return { text: "active", cls: "st-ok" };
  const days = Math.floor((new Date(end).getTime() - Date.now()) / 86400000);
  if (Number.isNaN(days)) return { text: "active", cls: "st-ok" };
  if (days < 0) return { text: "expired", cls: "st-expired" };
  if (days <= 14) return { text: `${days}d left`, cls: "st-warn" };
  if (days <= 30) return { text: `${days}d left`, cls: "st-soon" };
  return { text: `${days}d`, cls: "st-ok" };
}

function buildTlsTree() {
  const rootId = Number(state.selectedRootId);
  const root = selectedRoot();
  const tlsForRoot = state.tls.filter((t) => Number(t.root_ca_id || 1) === rootId);
  const intermediates = tlsForRoot
    .filter((t) => t.cert_level === "intermediate")
    .sort((a, b) => String(a.common_name).localeCompare(String(b.common_name)));
  const leaves = tlsForRoot.filter((t) => t.cert_level !== "intermediate");
  const leavesByParent = new Map();
  leaves.forEach((leaf) => {
    const key = leaf.parent_cert_id || "__root__";
    if (!leavesByParent.has(key)) leavesByParent.set(key, []);
    leavesByParent.get(key).push(leaf);
  });
  leavesByParent.forEach((rows) => rows.sort((a, b) => String(a.common_name).localeCompare(String(b.common_name))));

  if (!root) return [];
  const rootNode = {
    item: {
      id: `root-${root.id}`,
      root_id: Number(root.id),
      is_root_row: true,
      cert_level: "root",
      common_name: root.common_name,
      organization: root.organization,
      not_before: root.not_before,
      not_after: root.not_after,
      is_revoked: Boolean(root.is_revoked),
      revoked_reason: root.revoked_reason || "",
    },
    children: [],
  };
  intermediates.forEach((inter) => {
    const children = (leavesByParent.get(inter.id) || []).map((l) => ({ item: l, children: [] }));
    leavesByParent.delete(inter.id);
    rootNode.children.push({ item: inter, children });
  });
  (leavesByParent.get("__root__") || []).forEach((l) => rootNode.children.push({ item: l, children: [] }));
  leavesByParent.delete("__root__");
  Array.from(leavesByParent.values()).flat().forEach((l) => rootNode.children.push({ item: l, children: [] }));
  return [rootNode];
}

function renderCertTreeNodes(container, nodes, level) {
  nodes.forEach((node) => {
    const item = node.item;
    const hasChildren = node.children && node.children.length > 0;
    const collapsed = Boolean(state.collapsedNodes[item.id]);
    const li = document.createElement("li");
    li.classList.add(`depth-${Math.min(level, 2)}`);
    if (state.selected && state.selected.id === item.id) li.classList.add("active");

    if (hasChildren) {
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "tree-toggle";
      toggle.textContent = collapsed ? "▸" : "▾";
      toggle.setAttribute("aria-label", collapsed ? "Expand" : "Collapse");
      toggle.addEventListener("click", (e) => {
        e.stopPropagation();
        state.collapsedNodes[item.id] = !collapsed;
        renderList();
      });
      li.appendChild(toggle);
    } else {
      const spacer = document.createElement("span");
      spacer.className = "tree-spacer";
      li.appendChild(spacer);
    }

    const left = document.createElement("div");
    left.className = "tree-label";
    left.textContent = `${item.common_name} (${item.cert_level || "leaf"})`;
    const right = document.createElement("small");
    const st = certExpiryStatus(item);
    right.className = `tree-status ${st.cls}`;
    right.textContent = st.text;
    li.append(left, right);
    li.addEventListener("click", () => selectCertificate(item));
    container.appendChild(li);

    if (hasChildren && !collapsed) {
      renderCertTreeNodes(container, node.children, level + 1);
    }
  });
}

function renderList() {
  renderFirstRun();
  const list = el("cert-list");
  list.innerHTML = "";
  if (state.tab === "tls") {
    const tree = buildTlsTree();
    if (!tree.length) {
      const li = document.createElement("li");
      li.className = "tree-empty";
      li.textContent = "No certificates yet for this organization.";
      list.appendChild(li);
      return;
    }
    renderCertTreeNodes(list, tree, 0);
  } else {
    [...state.ssh].forEach((item) => {
      const li = document.createElement("li");
      if (state.selected && state.selected.id === item.id) li.classList.add("active");
      const left = document.createElement("div");
      left.className = "tree-label";
      left.textContent = `${item.ssh_username || "user"}@${item.machine_name || "machine"}`;
      const right = document.createElement("small");
      const st = certExpiryStatus(item);
      right.className = `tree-status ${st.cls}`;
      right.textContent = st.text;
      li.append(left, right);
      li.addEventListener("click", () => selectCertificate(item));
      list.appendChild(li);
    });
  }
}

async function selectCertificate(item) {
  state.selected = item;
  state.selectedDetail = null;
  state.deployGuide = null;
  if (!item.is_root_row && state.tab === "tls") {
    el("deploy-cert-path").value = "";
    el("deploy-key-path").value = "";
    el("deploy-chain-path").value = "";
    el("deploy-reload-cmd").value = "";
  }
  el("cert-action-status").textContent = "Loading certificate details...";
  renderList();
  renderDetails();
  await loadSelectedDetail();
}

async function getTlsDetail(id) {
  if (state.tlsDetailCache[id]) return state.tlsDetailCache[id];
  const detail = await api(`/api/v1/certificates/tls/${id}`);
  state.tlsDetailCache[id] = detail;
  return detail;
}

async function loadSelectedDetail() {
  if (!state.selected) return;
  try {
    if (state.selected.is_root_row) {
      state.selectedDetail = await api(`/api/v1/certificates/root/${state.selected.root_id}`);
    } else if (state.tab === "tls") {
      state.selectedDetail = await getTlsDetail(state.selected.id);
    } else {
      state.selectedDetail = await api(`/api/v1/certificates/ssh/${state.selected.id}`);
    }
    el("cert-action-status").textContent = "";
    renderDetails();
  } catch (err) {
    el("cert-action-status").textContent = `Unable to load details: ${err.message}`;
  }
}

function deployArtifact(title, bodyText, copyLabel = "Copy", secret = false) {
  const wrap = document.createElement("article");
  wrap.className = "artifact";
  const head = document.createElement("div");
  head.className = "artifact-head";
  const h = document.createElement("h5");
  h.textContent = title;
  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.textContent = copyLabel;
  copyBtn.addEventListener("click", async () => {
    const ok = await copyTextToClipboard(bodyText);
    flashCopyFeedback(copyBtn, ok);
    el("cert-action-status").textContent = ok ? `${title} copied to clipboard.` : `Unable to copy ${title}.`;
  });
  const pre = document.createElement("pre");
  pre.textContent = bodyText;
  if (secret) {
    pre.hidden = true;
    const masked = document.createElement("div");
    masked.className = "value-text secret-masked";
    masked.textContent = "••••••••••••••••••••••••";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.textContent = "Show";
    toggle.addEventListener("click", () => {
      const show = pre.hidden;
      pre.hidden = !show;
      masked.hidden = show;
      toggle.textContent = show ? "Hide" : "Show";
    });
    head.append(h, toggle, copyBtn);
    wrap.append(head, masked, pre);
  } else {
    head.append(h, copyBtn);
    wrap.append(head, pre);
  }
  return wrap;
}

function defaultDeployReload(target) {
  if (target === "nginx") return "systemctl reload nginx";
  if (target === "nginx_docker_container") return "docker exec nginx nginx -s reload";
  if (target === "nginx_podman_container") return "podman exec nginx nginx -s reload";
  if (target === "apache") return "systemctl reload apache2";
  if (target === "haproxy") return "systemctl reload haproxy";
  if (target === "iis") return "iisreset";
  if (target === "kubernetes") return "kubectl rollout restart deployment/<ingress-controller>";
  return "systemctl restart <service-name>";
}

function defaultPathsForTarget(target, safeName) {
  if (target === "nginx_docker_container" || target === "nginx_podman_container") {
    return {
      cert: `/etc/nginx/ssl/${safeName}.crt`,
      key: `/etc/nginx/ssl/${safeName}.key`,
      chain: `/etc/nginx/ssl/${safeName}-fullchain.crt`,
      conf: "/etc/nginx/conf.d/wss.conf",
    };
  }
  if (target === "kubernetes") {
    return {
      cert: `/tmp/${safeName}.crt`,
      key: `/tmp/${safeName}.key`,
      chain: `/tmp/${safeName}-fullchain.crt`,
      conf: "/etc/nginx/conf.d/wss.conf",
    };
  }
  if (target === "iis") {
    return {
      cert: `C:\\\\certs\\\\${safeName}.crt`,
      key: `C:\\\\certs\\\\${safeName}.key`,
      chain: `C:\\\\certs\\\\${safeName}-fullchain.crt`,
      conf: "C:\\\\nginx\\\\conf\\\\wss.conf",
    };
  }
  return {
    cert: `/etc/ssl/certs/${safeName}.crt`,
    key: `/etc/ssl/private/${safeName}.key`,
    chain: `/etc/ssl/certs/${safeName}-fullchain.crt`,
    conf: "/etc/nginx/conf.d/wss.conf",
  };
}

function seedDeployDefaults(force = false) {
  if (!state.selected || state.selected.is_root_row) return;
  const safeName = String(state.selected.common_name || "service").replace(/[^a-zA-Z0-9.-]/g, "_");
  const target = el("deploy-target").value;
  const paths = defaultPathsForTarget(target, safeName);
  if (force || !el("deploy-cert-path").value) el("deploy-cert-path").value = paths.cert;
  if (force || !el("deploy-key-path").value) el("deploy-key-path").value = paths.key;
  if (force || !el("deploy-chain-path").value) el("deploy-chain-path").value = paths.chain;
  if (force || !el("deploy-nginx-conf-path").value) el("deploy-nginx-conf-path").value = paths.conf;
  if (force || !el("deploy-container-name").value) el("deploy-container-name").value = "nginx";
  if (force || !el("deploy-ws-location").value) el("deploy-ws-location").value = "/ws/";
  if (force || !el("deploy-ws-upstream").value) el("deploy-ws-upstream").value = "http://127.0.0.1:3000";
  if (force || !el("deploy-reload-cmd").value) el("deploy-reload-cmd").value = defaultDeployReload(target);
}

function renderDeploymentAssistant() {
  const panel = el("deploy-assistant");
  const cert = state.selected;
  if (!cert || cert.is_root_row || state.tab !== "tls" || cert.cert_level === "intermediate") {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  seedDeployDefaults(false);
  const profile = DEPLOY_PROFILES[el("deploy-target").value] || DEPLOY_PROFILES.custom;
  const guide = state.deployGuide;
  const summary = guide
    ? {
        certificate_type: guide.certificate.cert_level,
        target_software: guide.target,
        certificate_name: guide.certificate.common_name,
        include_intermediate_certificate: guide.certificate.has_intermediate_chain ? "Yes" : "No",
        private_key_available_for_download: guide.certificate.allow_private_key_export,
      }
    : {
        certificate_type: cert.cert_level || "leaf",
        target_software: profile.label,
        certificate_name: cert.common_name || "",
        include_intermediate_certificate: cert.cert_level === "leaf" ? "Yes (recommended)" : "Not required",
        private_key_available_for_download: state.selectedDetail ? Boolean(state.selectedDetail.allow_private_key_export) : "Unknown (click Generate)",
      };
  renderObjectAsTable(el("deploy-summary"), summary);
  const steps = el("deploy-steps");
  steps.innerHTML = "";
  const toRender = guide?.steps || profile.steps;
  toRender.forEach((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    steps.appendChild(li);
  });
  const artifacts = el("deploy-artifacts");
  artifacts.innerHTML = "";
  if (!guide) {
    artifacts.appendChild(deployArtifact(
      "Next step",
      "Click \"Generate Deployment Plan\" to build software-specific commands and ready-to-use certificate artifacts."
    ));
    return;
  }
  if (Array.isArray(guide.commands)) {
    artifacts.appendChild(deployArtifact("Generated deployment commands", guide.commands.join("\n\n"), "Copy commands"));
  }
  artifacts.appendChild(deployArtifact("Leaf certificate (PEM)", guide.artifacts?.leaf_cert_pem || "Unavailable", "Copy PEM"));
  artifacts.appendChild(deployArtifact("Intermediate certificate (PEM)", guide.artifacts?.intermediate_cert_pem || "No intermediate linked", "Copy PEM"));
  artifacts.appendChild(deployArtifact("Full chain certificate (PEM)", guide.artifacts?.full_chain_pem || "Unavailable", "Copy PEM"));
  artifacts.appendChild(deployArtifact("Private key (PEM)", guide.artifacts?.private_key_pem || "Unavailable", "Copy key", true));
  if (guide.artifacts?.nginx_websocket_conf) {
    artifacts.appendChild(deployArtifact("Nginx secure WebSocket config", guide.artifacts.nginx_websocket_conf, "Copy config"));
  }
  if (Array.isArray(guide.warnings) && guide.warnings.length) {
    artifacts.appendChild(deployArtifact("Warnings", guide.warnings.join("\n"), "Copy warnings"));
  }
}

function renderDetails() {
  if (!state.selected) {
    el("cert-empty").hidden = false;
    el("cert-detail").hidden = true;
    return;
  }
  el("cert-empty").hidden = true;
  el("cert-detail").hidden = false;
  const s = state.selected;
  const d = state.selectedDetail || s;
  if (s.is_root_row) {
    el("cert-title").textContent = s.common_name;
    el("cert-subtitle").textContent = `Organization: ${s.organization}`;
    el("cert-options").textContent = `Type: Root CA | Valid: ${new Date(s.not_before).toLocaleDateString()} -> ${new Date(s.not_after).toLocaleDateString()} | Status: ${s.is_revoked ? "revoked" : "active"}`;
    renderObjectAsTable(el("cert-json"), d, ["id", "common_name", "organization", "description", "not_before", "not_after", "is_revoked", "revoked_at", "revoked_reason", "cipher", "key_length", "cert_pem"]);
    el("act-renew").disabled = false;
    el("act-revoke").disabled = false;
    el("act-publish").disabled = true;
    el("act-delete").disabled = true;
    el("act-export-public").disabled = true;
    el("act-export-private").disabled = true;
    renderDeploymentAssistant();
    return;
  }
  el("act-publish").disabled = false;
  el("act-delete").disabled = false;
  el("act-export-public").disabled = false;
  el("act-export-private").disabled = !s.allow_private_key_export;
  el("act-renew").disabled = state.tab !== "tls";
  el("act-revoke").disabled = false;
  if (state.tab === "tls") {
    el("cert-title").textContent = s.common_name;
    el("cert-subtitle").textContent = `${s.machine_name || ""} ${s.ip_address || ""}`.trim();
    el("cert-options").textContent = `Level: ${s.cert_level} | Cipher: ${s.cipher} | Key: ${s.key_length}`;
    renderObjectAsTable(el("cert-json"), d, [
      "id",
      "common_name",
      "serial_hex",
      "cert_level",
      "parent_cert_id",
      "cipher",
      "key_length",
      "valid_from",
      "valid_to",
      "is_revoked",
      "revoked_reason",
      "allow_private_key_export",
      "cert_pem",
      "private_key_pem",
    ]);
    renderDeploymentAssistant();
  } else {
    el("cert-title").textContent = `${s.ssh_username}@${s.machine_name}`;
    el("cert-subtitle").textContent = `Fingerprint: ${s.fingerprint}`;
    el("cert-options").textContent = `Cipher: ${s.cipher} | Key: ${s.key_length}`;
    renderObjectAsTable(el("cert-json"), d, [
      "id",
      "algorithm",
      "fingerprint",
      "ssh_username",
      "machine_name",
      "valid_from",
      "valid_to",
      "is_revoked",
      "revoked_reason",
      "allow_private_key_export",
      "public_key",
      "private_key",
    ]);
    el("deploy-assistant").hidden = true;
  }
}

async function buildDeploymentGuide() {
  if (!state.selected || state.selected.is_root_row || state.tab !== "tls") return;
  const target = el("deploy-target").value;
  const certPath = el("deploy-cert-path").value.trim();
  const keyPath = el("deploy-key-path").value.trim();
  const chainPath = el("deploy-chain-path").value.trim();
  const reloadCommand = el("deploy-reload-cmd").value.trim();
  const nginxConfPath = el("deploy-nginx-conf-path").value.trim();
  const containerName = el("deploy-container-name").value.trim();
  const websocketLocation = el("deploy-ws-location").value.trim();
  const websocketUpstream = el("deploy-ws-upstream").value.trim();
  const useSudo = document.querySelector("input[name='deploy_use_sudo']:checked")?.value === "yes";
  if (!certPath || !keyPath) {
    el("cert-action-status").textContent = "Certificate and key path are required for deployment plan generation.";
    return;
  }
  try {
    el("cert-action-status").textContent = "Generating deployment plan...";
    state.deployGuide = await api(`/api/v1/deploy/tls/${state.selected.id}/guide`, {
      method: "POST",
      body: JSON.stringify({
        target,
        cert_path: certPath,
        key_path: keyPath,
        chain_path: chainPath || certPath,
        reload_command: reloadCommand || defaultDeployReload(target),
        use_sudo: useSudo,
        container_name: containerName,
        nginx_conf_path: nginxConfPath || "/etc/nginx/conf.d/wss.conf",
        websocket_location: websocketLocation || "/ws/",
        websocket_upstream: websocketUpstream || "http://127.0.0.1:3000",
      }),
    });
    el("cert-action-status").textContent = "Deployment plan generated.";
    renderDeploymentAssistant();
  } catch (err) {
    el("cert-action-status").textContent = `Deployment plan generation failed: ${err.message}`;
  }
}

function fillOwnerEnvSelects() {
  const ownerOpts = state.owners.map((o) => `<option value="${o}">${o}</option>`).join("");
  const envOpts = state.environments.map((e) => `<option value="${e}">${e}</option>`).join("");
  ["cf-owner", "im-owner", "mm-owner", "host-modal-owner", "mon-owner"].forEach((id) => {
    const n = el(id);
    if (!n) return;
    const prev = n.value;
    n.innerHTML = ownerOpts;
    if (prev && state.owners.includes(prev)) n.value = prev;
  });
  ["cf-env", "im-env", "mm-env", "host-modal-env", "mon-env"].forEach((id) => {
    const n = el(id);
    if (!n) return;
    const prev = n.value;
    n.innerHTML = envOpts;
    if (prev && state.environments.includes(prev)) n.value = prev;
  });
}

function renderListEditor(containerId, items, onChange) {
  const c = el(containerId);
  if (!c) return;
  c.innerHTML = "";
  items.forEach((val, idx) => {
    const row = document.createElement("div");
    row.className = "list-row";
    const span = document.createElement("span");
    span.className = "list-val";
    span.textContent = val;
    const rm = document.createElement("button");
    rm.type = "button";
    rm.className = "list-btn";
    rm.textContent = "−";
    rm.title = "Remove";
    rm.addEventListener("click", () => {
      items.splice(idx, 1);
      onChange();
    });
    row.append(span, rm);
    c.appendChild(row);
  });
  const addRow = document.createElement("div");
  addRow.className = "list-row";
  const inp = document.createElement("input");
  inp.placeholder = "add…";
  const add = document.createElement("button");
  add.type = "button";
  add.className = "list-btn";
  add.textContent = "+";
  add.title = "Add";
  const doAdd = () => {
    const v = inp.value.trim();
    if (v && !items.includes(v)) {
      items.push(v);
      onChange();
    }
  };
  add.addEventListener("click", doAdd);
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      doAdd();
    }
  });
  addRow.append(inp, add);
  c.appendChild(addRow);
}

function refreshOwnerEnvUi() {
  renderListEditor("owners-editor", state.owners, refreshOwnerEnvUi);
  renderListEditor("environments-editor", state.environments, refreshOwnerEnvUi);
  fillOwnerEnvSelects();
}

function parseStringArray(raw, fallback) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length) return parsed.map((x) => String(x));
  } catch (_) {}
  return fallback.slice();
}

async function loadDefaults() {
  const data = await api("/api/v1/settings/defaults");
  state.defaults = data;
  const setIfValid = (id, val) => {
    const s = el(id);
    if (s && Array.from(s.options).some((o) => o.value === String(val))) s.value = String(val);
  };
  // Apply saved ciphers to the settings selects and to the certificate-creation dialogs.
  setIfValid("default_tls_cipher", data.default_tls_cipher);
  setIfValid("default_ssh_cipher", data.default_ssh_cipher);
  setIfValid("cf-tls-cipher", data.default_tls_cipher);
  setIfValid("cf-ssh-cipher", data.default_ssh_cipher);
  setIfValid("im-tls-cipher", data.default_tls_cipher);
  // Rebuild the key-length options to match the chosen ciphers before applying the saved lengths.
  applyKeyLengthOptions();
  setIfValid("default_tls_key_length", data.default_tls_key_length);
  setIfValid("default_ssh_key_length", data.default_ssh_key_length);
  setIfValid("cf-tls-key-length", data.default_tls_key_length);
  setIfValid("cf-ssh-key-length", data.default_ssh_key_length);
  setIfValid("im-tls-key-length", data.default_tls_key_length);
  if (el("public_base_url")) el("public_base_url").value = data.public_base_url || "";
  if (el("crl_base_url")) el("crl_base_url").value = data.crl_base_url || "";
  refreshCipherCompatibilityHints();
  state.owners = parseStringArray(data.cert_owners_json, ["lab-ops", "security", "devops"]);
  state.environments = parseStringArray(data.cert_environments_json, ["production", "staging", "internal-lab", "development"]);
  refreshOwnerEnvUi();
}

function fillMachineSelectOptions() {
  const sel = el("mon-host-select");
  if (!sel) return;
  const prev = state.monHostId || sel.value;
  sel.innerHTML = "";
  const blank = document.createElement("option");
  blank.value = "";
  blank.textContent = state.machines.length ? "— select a host —" : "no hosts yet";
  sel.appendChild(blank);
  state.machines.forEach((m) => {
    const o = document.createElement("option");
    o.value = m.id;
    o.textContent = `${m.hostname} (${m.ip_address})`;
    sel.appendChild(o);
  });
  if (prev && state.machines.find((m) => m.id === prev)) {
    sel.value = prev;
    state.monHostId = prev;
  } else {
    state.monHostId = "";
  }
}

function ensureSelectValue(id, value) {
  const s = el(id);
  if (!s) return;
  if (value && !Array.from(s.options).some((o) => o.value === value)) {
    const o = document.createElement("option");
    o.value = value;
    o.textContent = value;
    s.appendChild(o);
  }
  s.value = value || "";
}

function renderMonEditor() {
  const fields = el("mon-host-fields");
  if (!fields) return;
  const m = state.machines.find((x) => x.id === state.monHostId);
  if (!m) {
    fields.hidden = true;
    return;
  }
  fields.hidden = false;
  el("mon-name").value = m.hostname || "";
  el("mon-ip").value = m.ip_address || "";
  ensureSelectValue("mon-owner", m.owner || "");
  ensureSelectValue("mon-env", m.environment || "");
  el("mon-os").value = m.os_type || "";
  renderMonPortsEditor(m.id);
}

function renderMonPortsEditor(mid) {
  const c = el("mon-ports-editor");
  if (!c) return;
  c.innerHTML = "";
  const rows = state.machineMonitorRows.filter((r) => r.machine_id === mid);
  if (!rows.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No monitored ports yet. Add one below.";
    c.appendChild(p);
    return;
  }
  const byPort = new Map();
  rows.forEach((r) => {
    if (!byPort.has(r.port)) byPort.set(r.port, []);
    byPort.get(r.port).push(r);
  });
  Array.from(byPort.keys()).sort((a, b) => a - b).forEach((port) => {
    const group = byPort.get(port);
    const portDiv = document.createElement("div");
    portDiv.className = "port-group";
    const head = document.createElement("div");
    head.className = "list-row";
    const title = document.createElement("strong");
    title.textContent = `Port ${port}`;
    const rmPort = document.createElement("button");
    rmPort.type = "button";
    rmPort.className = "list-btn";
    rmPort.textContent = "− port";
    rmPort.title = "Remove this port and all its virtual hosts";
    rmPort.addEventListener("click", async () => {
      for (const r of group) {
        await api(`/api/v1/machines/monitor/ports/${r.id}`, { method: "DELETE" }).catch(() => {});
      }
      await refreshMonAfterChange();
    });
    head.append(title, rmPort);
    portDiv.appendChild(head);

    const vwrap = document.createElement("div");
    vwrap.className = "vhost-wrap";
    group
      .slice()
      .sort((a, b) => String(a.sni_host).localeCompare(String(b.sni_host)))
      .forEach((r) => {
        const row = document.createElement("div");
        row.className = "list-row";
        const span = document.createElement("span");
        span.className = "list-val";
        span.textContent = r.sni_host ? r.sni_host : "(default host)";
        const rm = document.createElement("button");
        rm.type = "button";
        rm.className = "list-btn";
        rm.textContent = "−";
        rm.addEventListener("click", async () => {
          await api(`/api/v1/machines/monitor/ports/${r.id}`, { method: "DELETE" }).catch(() => {});
          await refreshMonAfterChange();
        });
        row.append(span, rm);
        vwrap.appendChild(row);
      });
    const addRow = document.createElement("div");
    addRow.className = "list-row";
    const inp = document.createElement("input");
    inp.placeholder = "add virtual host (SNI)…";
    const add = document.createElement("button");
    add.type = "button";
    add.className = "list-btn";
    add.textContent = "+ vhost";
    const doAdd = async () => {
      const v = inp.value.trim();
      if (!v) return;
      try {
        await api("/api/v1/machines/monitor/ports", {
          method: "POST",
          body: JSON.stringify({ machine_id: mid, port, sni_host: v }),
        });
        await refreshMonAfterChange();
      } catch (err) {
        el("mon-editor-status").textContent = err.message;
      }
    };
    add.addEventListener("click", doAdd);
    inp.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        doAdd();
      }
    });
    addRow.append(inp, add);
    vwrap.appendChild(addRow);
    portDiv.appendChild(vwrap);
    c.appendChild(portDiv);
  });
}

async function refreshMonAfterChange() {
  await loadMachineMonitorRows();
  renderMonPortsEditor(state.monHostId);
}

function formatBytes(n) {
  const b = Number(n) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}

async function loadBackupSettings() {
  const d = await api("/api/v1/settings/backup");
  const en = document.querySelector(`input[name='backup_enabled'][value='${d.enabled ? "yes" : "no"}']`);
  if (en) en.checked = true;
  el("backup-frequency").value = String(d.frequency_hours || 24);
  el("backup-retention").value = String(d.retention || 5);
  const sk = document.querySelector(`input[name='backup_skip'][value='${d.skip_unchanged ? "yes" : "no"}']`);
  if (sk) sk.checked = true;
  const mode = d.encryption_mode || "none";
  const enc = document.querySelector(`input[name='backup_encryption_mode'][value='${mode}']`);
  if (enc) enc.checked = true;
  const status = el("backup-passphrase-status");
  if (status) {
    status.textContent = d.has_passphrase
      ? "A backup passphrase is set. Leave the field blank to keep it."
      : "No passphrase set yet — enter one to enable passphrase encryption.";
  }
  syncBackupEncRows();
  await loadBackupRecipients().catch(() => {});
}

function syncBackupEncRows() {
  const mode = (document.querySelector("input[name='backup_encryption_mode']:checked") || {}).value || "none";
  el("backup-enc-passphrase").hidden = mode !== "passphrase";
  el("backup-passphrase-status").hidden = mode !== "passphrase";
  el("backup-enc-envelope").hidden = mode !== "envelope";
  el("backup-recipients-section").hidden = mode !== "envelope";
}

async function loadBackupRecipients() {
  const res = await api("/api/v1/backup/recipients");
  const tbody = el("backup-recipients-tbody");
  tbody.innerHTML = "";
  asItems(res).forEach((r) => {
    const tr = document.createElement("tr");
    [r.name, (r.fingerprint_sha256 || "").slice(0, 24) + "…", r.created_at ? new Date(r.created_at).toLocaleDateString() : "—"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdA = document.createElement("td");
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Remove";
    del.addEventListener("click", async () => {
      if (!confirm(`Remove recipient "${r.name}"?`)) return;
      await api(`/api/v1/backup/recipients/${r.id}`, { method: "DELETE" });
      await loadBackupRecipients();
    });
    tdA.appendChild(del);
    tr.appendChild(tdA);
    tbody.appendChild(tr);
  });
}

function arrayBufferToBase64(buf) {
  let binary = "";
  const bytes = new Uint8Array(buf);
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function syncBackupDestRows() {
  const t = el("backup-dest-type").value;
  el("backup-dest-path").hidden = t !== "path";
  el("backup-dest-sftp").hidden = t !== "sftp";
  document.querySelectorAll(".backup-remote-only").forEach((n) => (n.hidden = t === "local"));
  const auth = (document.querySelector("input[name='sftp_auth']:checked") || {}).value || "password";
  el("backup-sftp-pw-row").hidden = auth !== "password";
  el("backup-sftp-key-row").hidden = auth !== "key";
  el("backup-sftp-kp-row").hidden = auth !== "key";
}

function syncCrlDestRows() {
  const t = el("crl-dest-type").value;
  el("crl-dest-path").hidden = t !== "path";
  el("crl-dest-sftp").hidden = t !== "sftp";
  const auth = (document.querySelector("input[name='crl_sftp_auth']:checked") || {}).value || "password";
  el("crl-sftp-pw-row").hidden = auth !== "password";
  el("crl-sftp-key-row").hidden = auth !== "key";
  el("crl-sftp-kp-row").hidden = auth !== "key";
}

function syncDeployHtmlDestRows() {
  const t = el("deployhtml-dest-type").value;
  el("deployhtml-dest-path").hidden = t !== "path";
  el("deployhtml-dest-sftp").hidden = t !== "sftp";
  const auth = (document.querySelector("input[name='deployhtml_sftp_auth']:checked") || {}).value || "password";
  el("deployhtml-sftp-pw-row").hidden = auth !== "password";
  el("deployhtml-sftp-key-row").hidden = auth !== "key";
  el("deployhtml-sftp-kp-row").hidden = auth !== "key";
}

async function loadDeployHtmlRemoteSettings() {
  const d = await api("/api/v1/settings/deploy-html/remote");
  el("deployhtml-dest-type").value = d.dest_type || "local";
  el("deployhtml-remote-path").value = d.remote_path || "";
  el("deployhtml-sftp-host").value = d.sftp_host || "";
  el("deployhtml-sftp-port").value = String(d.sftp_port || 22);
  el("deployhtml-sftp-user").value = d.sftp_user || "";
  el("deployhtml-sftp-dir").value = d.sftp_remote_dir || "";
  const auth = document.querySelector(`input[name='deployhtml_sftp_auth'][value='${d.sftp_auth || "password"}']`);
  if (auth) auth.checked = true;
  el("deployhtml-status").textContent = [
    d.has_sftp_password ? "SFTP password stored" : null,
    d.has_sftp_key ? "SFTP key stored" : null,
  ].filter(Boolean).join(" · ");
  syncDeployHtmlDestRows();
}

async function loadCrlRemoteSettings() {
  const d = await api("/api/v1/settings/crl/remote");
  el("crl-dest-type").value = d.dest_type || "local";
  el("crl-remote-path").value = d.remote_path || "";
  el("crl-sftp-host").value = d.sftp_host || "";
  el("crl-sftp-port").value = String(d.sftp_port || 22);
  el("crl-sftp-user").value = d.sftp_user || "";
  el("crl-sftp-dir").value = d.sftp_remote_dir || "";
  const auth = document.querySelector(`input[name='crl_sftp_auth'][value='${d.sftp_auth || "password"}']`);
  if (auth) auth.checked = true;
  el("crl-remote-status").textContent = [
    d.has_sftp_password ? "SFTP password stored" : null,
    d.has_sftp_key ? "SFTP key stored" : null,
  ].filter(Boolean).join(" · ");
  syncCrlDestRows();
}

async function loadBackupRemoteSettings() {
  const d = await api("/api/v1/settings/backup/remote");
  el("backup-dest-type").value = d.dest_type || "local";
  el("backup-remote-retention").value = String(d.remote_retention || 7);
  el("backup-remote-path").value = d.remote_path || "";
  el("backup-sftp-host").value = d.sftp_host || "";
  el("backup-sftp-port").value = String(d.sftp_port || 22);
  el("backup-sftp-user").value = d.sftp_user || "";
  el("backup-sftp-dir").value = d.sftp_remote_dir || "";
  const auth = document.querySelector(`input[name='sftp_auth'][value='${d.sftp_auth || "password"}']`);
  if (auth) auth.checked = true;
  el("backup-remote-status").textContent = [
    d.has_sftp_password ? "SFTP password stored" : null,
    d.has_sftp_key ? "SFTP key stored" : null,
  ].filter(Boolean).join(" · ");
  syncBackupDestRows();
}

async function loadBackupList() {
  const res = await api("/api/v1/backup/list");
  const tbody = el("backup-tbody");
  tbody.innerHTML = "";
  const items = asItems(res);
  if (!items.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.className = "hint";
    td.textContent = "No backups yet.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  items.forEach((b) => {
    const tr = document.createElement("tr");
    [b.name, formatBytes(b.size_bytes), b.created_at ? new Date(b.created_at).toLocaleString() : "—"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

async function importBackupFile(file) {
  if (!file) return;
  if (!confirm(`Restore the database from "${file.name}"? This OVERWRITES current data.`)) return;
  const headers = { Authorization: `Bearer ${state.token}`, "Content-Type": "application/octet-stream" };
  // Encrypted (.ezbak) files: unlock with a passphrase or a recipient private key.
  if (file.name.endsWith(".ezbak")) {
    const method = prompt('Unlock this encrypted backup with:\n  "p" = passphrase\n  "k" = recipient private key', "p");
    if (method === null) return;
    if (method.trim().toLowerCase().startsWith("k")) {
      const pem = prompt("Paste the recipient PRIVATE key (PEM):");
      if (!pem) return;
      const keyPass = prompt("Private key passphrase (leave blank if none):") || "";
      el("backup-output").textContent = "Restoring...";
      try {
        const buf = await file.arrayBuffer();
        await api("/api/v1/backup/restore", {
          method: "POST",
          body: JSON.stringify({ data_b64: arrayBufferToBase64(buf), private_key_pem: pem, key_passphrase: keyPass || null }),
        });
        el("backup-output").textContent = "Database restored. Reloading…";
        setTimeout(() => window.location.reload(), 1200);
      } catch (err) {
        el("backup-output").textContent = `Restore failed: ${err.message}`;
      }
      return;
    }
    const pass = prompt("Backup passphrase (leave blank to use the one configured on this server):");
    if (pass) headers["X-Backup-Passphrase"] = pass;
  }
  el("backup-output").textContent = "Restoring...";
  try {
    const buf = await file.arrayBuffer();
    const res = await fetch("/api/v1/backup/import", { method: "POST", headers, body: buf });
    const txt = await res.text();
    if (!res.ok) {
      let msg = txt;
      try { msg = JSON.parse(txt).error || txt; } catch (_) {}
      throw new Error(msg || `HTTP ${res.status}`);
    }
    el("backup-output").textContent = "Database restored. Reloading…";
    setTimeout(() => window.location.reload(), 1200);
  } catch (err) {
    el("backup-output").textContent = `Restore failed: ${err.message}`;
  }
}

async function loadMachineMonitorSettings() {
  const data = await api("/api/v1/settings/machine-monitor");
  state.machineMonitorSettings = data;
  const enabled = data.monitor_enabled !== false;
  const enabledInput = document.querySelector(`#machine-monitor-settings-form input[name='monitor_enabled'][value='${enabled ? "yes" : "no"}']`);
  if (enabledInput) enabledInput.checked = true;
  el("mm-frequency-hours").value = String(data.frequency_hours || 24);
  el("mm-default-ports").value = data.default_ports_csv || "443,8443";
  el("mm-alert-webhook-url").value = data.alert_webhook_url || "";
  el("mm-alert-email-to").value = data.alert_email_to || "";
  el("mm-alert-cooldown-hours").value = String(data.alert_cooldown_hours || 24);
}

function monitorRowSeverity(item) {
  const days = Number(item.days_to_expiry);
  const status = String(item.status || "").toLowerCase();
  if (status === "expired" || days < 0) return "expired";
  if (status === "warning" || (Number.isFinite(days) && days <= 7)) return "warning";
  if (status === "error") return "warning";
  return "ok";
}

function renderMachineMonitorDetails(item) {
  const container = el("machine-cert-detail");
  const legend = el("machine-cert-legend");
  if (!item) {
    if (legend) legend.textContent = "Certificate details";
    container.textContent = "Select a monitored port row to view full certificate and chain details.";
    return;
  }
  if (legend) {
    const vhost = item.sni_host ? ` · vhost ${item.sni_host}` : "";
    legend.textContent = `Certificate details — ${item.hostname}:${item.port}${vhost}`;
  }
  container.innerHTML = "";
  const sev = statusDotClass(item.status).replace("dot-", "");
  const banner = document.createElement("p");
  banner.className = `diagnostic-banner diag-${sev}`;
  banner.textContent = item.diagnostic || "No scan yet.";
  container.appendChild(banner);

  const tlsSupport = Array.isArray(item.tls_support) ? item.tls_support : [];
  const tlsBox = document.createElement("div");
  tlsBox.className = "tls-support";
  const tlsTitle = document.createElement("h4");
  tlsTitle.textContent = "Accepted TLS protocols & ciphers";
  tlsBox.appendChild(tlsTitle);
  if (!tlsSupport.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No protocols recorded (run a scan).";
    tlsBox.appendChild(p);
  } else {
    const ul = document.createElement("ul");
    ul.className = "tls-support-list";
    tlsSupport.forEach((t) => {
      const li = document.createElement("li");
      const proto = document.createElement("strong");
      proto.textContent = t.protocol || "?";
      li.appendChild(proto);
      li.appendChild(document.createTextNode(`  ${t.cipher || ""}`));
      ul.appendChild(li);
    });
    tlsBox.appendChild(ul);
  }
  container.appendChild(tlsBox);

  const rawChain = Array.isArray(item.cert_chain) ? item.cert_chain : [];
  const seenChain = new Set();
  const chain = rawChain.filter((c) => {
    const key = c.serial_hex || `${c.subject}|${c.issuer}`;
    if (seenChain.has(key)) return false;
    seenChain.add(key);
    return true;
  });
  const leaf = chain[0] || {};
  const sans = Array.isArray(leaf.subject_alt_names) ? leaf.subject_alt_names : [];
  // The trust anchor is the top cert if it is self-signed (root was sent), otherwise the
  // issuer of the top cert (servers usually omit the root from the chain they present).
  const top = chain[chain.length - 1] || null;
  const issuerRoot = top
    ? (top.subject === top.issuer ? top.subject : top.issuer)
    : "—";

  const sanBox = document.createElement("div");
  sanBox.className = "tls-support";
  const sanTitle = document.createElement("h4");
  sanTitle.textContent = "Subject Alternative Names (valid for)";
  sanBox.appendChild(sanTitle);
  if (!sans.length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "None listed on the certificate.";
    sanBox.appendChild(p);
  } else {
    const ul = document.createElement("ul");
    ul.className = "san-list";
    sans.forEach((s) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      const host = String(s).includes(":") && !String(s).includes(".") ? `[${s}]` : s;
      a.href = `https://${host}:${item.port || 443}`;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = s;
      li.appendChild(a);
      ul.appendChild(li);
    });
    sanBox.appendChild(ul);
  }
  container.appendChild(sanBox);

  const holder = document.createElement("div");
  container.appendChild(holder);
  renderObjectAsTable(holder, {
    monitor_port_id: item.id,
    machine_id: item.machine_id,
    hostname: item.hostname,
    ip_address: item.ip_address,
    virtual_host: item.sni_host || "(default)",
    owner: item.owner,
    environment: item.environment,
    machine_certificate_count: item.machine_certificate_count,
    port: item.port,
    monitor_enabled: item.monitor_enabled,
    status: item.status,
    days_to_expiry: item.days_to_expiry,
    cert_not_before: item.cert_not_before,
    cert_not_after: item.cert_not_after,
    cert_subject: item.cert_subject,
    cert_issuer: item.cert_issuer,
    issuer_root: issuerRoot,
    signature_algorithm: leaf.signature_algorithm || "—",
    cert_serial_hex: item.cert_serial_hex,
    certificate_chain: chain,
    last_error: item.last_error,
    last_checked_at: item.last_checked_at,
  });
}

function renderMachineMonitorTable() {
  const tbody = el("machines-monitor-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (!state.machineMonitorRows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.textContent = "No monitored ports configured.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    renderMachineMonitorDetails(null);
    return;
  }

  state.machineMonitorRows.forEach((item) => {
    const tr = document.createElement("tr");
    const severity = monitorRowSeverity(item);
    if (severity === "warning") tr.classList.add("monitor-row-warning");
    if (severity === "expired") tr.classList.add("monitor-row-expired");
    if (state.selectedMachineMonitorRow && state.selectedMachineMonitorRow.id === item.id) {
      tr.classList.add("active");
    }

    const expiresText = item.cert_not_after ? new Date(item.cert_not_after).toLocaleString() : "—";
    const checkedText = item.last_checked_at ? new Date(item.last_checked_at).toLocaleString() : "Never";
    const statusText = item.status || "unknown";

    const values = [
      item.hostname,
      item.ip_address,
      item.sni_host ? `${item.port} (${item.sni_host})` : String(item.port),
      statusText,
      expiresText,
      checkedText,
    ];
    values.forEach((v, idx) => {
      const td = document.createElement("td");
      if (idx === 3) {
        const dot = document.createElement("span");
        dot.className = `status-dot ${statusDotClass(item.status)}`;
        td.appendChild(dot);
        td.appendChild(document.createTextNode(String(v || "—")));
      } else {
        td.textContent = String(v || "—");
      }
      tr.appendChild(td);
    });

    const actionTd = document.createElement("td");
    const actionWrap = document.createElement("div");
    actionWrap.className = "row-actions";
    const iconBtn = (icon, label) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "icon-btn";
      b.textContent = icon;
      b.title = label;
      b.setAttribute("aria-label", label);
      return b;
    };
    const scanBtn = iconBtn("⟳", "Scan now");
    scanBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await api(`/api/v1/machines/monitor/ports/${item.id}/scan`, { method: "POST" });
      await loadMachineMonitorRows();
      el("machines-output").textContent = `Scanned ${item.hostname}:${item.port}`;
    });
    const toggleBtn = iconBtn(
      item.monitor_enabled ? "⏸" : "▶",
      item.monitor_enabled ? "Disable monitoring" : "Enable monitoring",
    );
    toggleBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await api(`/api/v1/machines/monitor/ports/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ monitor_enabled: !item.monitor_enabled }),
      });
      await loadMachineMonitorRows();
      el("machines-output").textContent = `${item.hostname}:${item.port} monitoring ${item.monitor_enabled ? "disabled" : "enabled"}.`;
    });
    const editBtn = iconBtn("✎", "Edit port");
    editBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const raw = prompt(`New port for ${item.hostname}:${item.port}`, String(item.port));
      if (raw === null) return;
      const port = Number(String(raw).trim());
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        el("machines-output").textContent = "Invalid port. Please use a value between 1 and 65535.";
        return;
      }
      await api(`/api/v1/machines/monitor/ports/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ port }),
      });
      await loadMachineMonitorRows();
      el("machines-output").textContent = `Updated ${item.hostname} monitor port to ${port}.`;
    });
    const delBtn = iconBtn("🗑", "Delete");
    delBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm(`Delete monitor ${item.hostname}:${item.port}?`)) return;
      await api(`/api/v1/machines/monitor/ports/${item.id}`, { method: "DELETE" });
      if (state.selectedMachineMonitorRow?.id === item.id) {
        state.selectedMachineMonitorRow = null;
      }
      await loadMachineMonitorRows();
    });
    actionWrap.append(scanBtn, toggleBtn, editBtn, delBtn);
    actionTd.appendChild(actionWrap);
    tr.appendChild(actionTd);

    tr.addEventListener("click", () => {
      state.selectedMachineMonitorRow = item;
      renderMachineMonitorTable();
      renderMachineMonitorDetails(item);
    });
    tbody.appendChild(tr);
  });

  if (state.selectedMachineMonitorRow) {
    const fresh = state.machineMonitorRows.find((r) => r.id === state.selectedMachineMonitorRow.id);
    state.selectedMachineMonitorRow = fresh || null;
  }
  renderMachineMonitorDetails(state.selectedMachineMonitorRow || state.machineMonitorRows[0]);
}

async function loadMachineMonitorRows() {
  const out = await api("/api/v1/machines/monitor");
  state.machineMonitorRows = asItems(out);
  renderMachineMonitorTable();
}

async function loadMachinesPage() {
  state.machines = asItems(await api("/api/v1/machines"));
  fillOwnerEnvSelects();
  fillMachineSelectOptions();
  await loadMachineMonitorRows();
  renderMonEditor();
}

async function downloadApi(path, fallbackName) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { headers });
  if (!res.ok) throw new Error(`Download failed (${res.status})`);
  const blob = await res.blob();
  const dispo = res.headers.get("content-disposition") || "";
  const filename = (dispo.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function findOrCreateMachine(form) {
  try {
    const created = await api("/api/v1/machines", {
      method: "POST",
      body: JSON.stringify({
        hostname: form.hostname,
        ip_address: form.ip_address,
        owner: form.owner,
        environment: form.environment,
      }),
    });
    return created.id;
  } catch (_) {
    const all = asItems(await api("/api/v1/machines"));
    const found = all.find((m) => m.hostname === form.hostname && m.ip_address === form.ip_address);
    if (!found) throw new Error("Unable to create or find machine");
    return found.id;
  }
}

async function resolveHint() {
  const host = el("cf-hostname").value.trim();
  const ip = el("cf-ip").value.trim();
  try {
    if (host && !ip) {
      const out = await api(`/api/v1/network/resolve?hostname=${encodeURIComponent(host)}`);
      if (out.ips && out.ips.length) {
        el("cf-ip").value = out.ips[0];
        el("resolve-hint").textContent = `Suggested IPs: ${out.ips.join(", ")}`;
      }
      return;
    }
    if (ip && !host) {
      const out = await api(`/api/v1/network/resolve?ip=${encodeURIComponent(ip)}`);
      if (out.reverse_hostname) {
        el("cf-hostname").value = out.reverse_hostname;
        el("resolve-hint").textContent = `Reverse DNS: ${out.reverse_hostname}`;
      }
    }
  } catch (_) {
    el("resolve-hint").textContent = "DNS suggestion unavailable";
  }
}

async function loadLogs(filters = {}) {
  const actor = encodeURIComponent(filters.actor || "");
  const term = encodeURIComponent(filters.term || "");
  const [actions, access, security] = await Promise.all([
    api(`/api/v1/logs/actions?actor=${actor}&action=${term}`),
    api(`/api/v1/logs/access?actor=${actor}&path=${term}`),
    api(`/api/v1/logs/security?event_type=${term}&source_ip=${term}`),
  ]);
  renderLogTable(el(LOG_TABLE_CONFIG.actions.outputId), actions, LOG_TABLE_CONFIG.actions.columns);
  renderLogTable(el(LOG_TABLE_CONFIG.access.outputId), access, LOG_TABLE_CONFIG.access.columns);
  renderLogTable(el(LOG_TABLE_CONFIG.security.outputId), security, LOG_TABLE_CONFIG.security.columns);
}

// ---- Profile > sign-in security -----------------------------------------

function securityStatus(message) {
  el("security-output").textContent = message || "";
}

async function loadSecurityPage() {
  // Second factors are a property of the local account table. Under OIDC the
  // identity provider owns MFA, and there may be no local row at all.
  if (state.branding && state.branding.auth_mode === "oidc") {
    document.querySelectorAll("#page-profile .sec-card").forEach((n) => (n.hidden = true));
    securityStatus(
      "This server authenticates through an identity provider (OIDC). Manage two-factor authentication and passkeys there."
    );
    return;
  }

  const data = await api("/api/v1/mfa/status");
  state.security = data;

  // --- TOTP ---
  el("totp-badge").textContent = data.totp_enabled ? "On" : "Off";
  el("totp-badge").className = `sec-badge ${data.totp_enabled ? "sec-badge-on" : "sec-badge-off"}`;
  el("totp-state").textContent = data.totp_enabled
    ? `Enabled. ${data.recovery_codes_remaining} recovery code${data.recovery_codes_remaining === 1 ? "" : "s"} left.`
    : data.require_mfa
    ? "This server requires two-factor authentication — set it up now, or you'll be asked at your next sign-in."
    : "Not set up. Turn this on so a stolen password isn't enough to sign in as you.";
  el("totp-start-btn").hidden = data.totp_enabled;
  el("totp-disable-btn").hidden = !data.totp_enabled;
  el("totp-codes-btn").hidden = !data.totp_enabled;
  if (data.totp_enabled) el("totp-setup").hidden = true;

  // --- Passkeys ---
  const keys = data.passkeys || [];
  el("passkey-badge").textContent = keys.length ? `${keys.length} registered` : "None";
  el("passkey-badge").className = `sec-badge ${keys.length ? "sec-badge-on" : "sec-badge-off"}`;
  const supported = data.passkeys_supported && passkeysAvailable();
  el("passkey-state").textContent = !data.passkeys_supported
    ? "Passkeys are not enabled on this server. An administrator needs to set WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN."
    : !passkeysAvailable()
    ? "This browser can't register passkeys here — they require an HTTPS connection."
    : keys.length
    ? "Use any of these to sign in without typing a password."
    : "Register this device to sign in with your fingerprint, face, PIN, or a security key.";
  el("passkey-add-btn").disabled = !supported;
  el("passkey-add-row").hidden = !supported;

  const table = el("passkeys-table");
  const tbody = el("passkeys-tbody");
  tbody.innerHTML = "";
  table.hidden = keys.length === 0;
  keys.forEach((key) => {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = key.name;
    const created = document.createElement("td");
    created.textContent = new Date(key.created_at).toLocaleString();
    const used = document.createElement("td");
    used.textContent = key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "never";
    const actions = document.createElement("td");
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      if (!confirm(`Remove the passkey "${key.name}"? That device will no longer be able to sign in.`)) return;
      try {
        await api(`/api/v1/mfa/passkeys/${key.id}`, { method: "DELETE" });
        securityStatus("Passkey removed.");
        await loadSecurityPage();
      } catch (err) {
        securityStatus(err.message);
      }
    });
    actions.appendChild(remove);
    tr.append(name, created, used, actions);
    tbody.appendChild(tr);
  });
}

async function startTotpSetup() {
  try {
    const setup = await api("/api/v1/mfa/totp/setup", { method: "POST" });
    el("totp-qr").src = setup.qr_data_url;
    el("totp-secret").textContent = setup.secret;
    el("totp-code").value = "";
    el("totp-setup").hidden = false;
    el("recovery-codes-box").hidden = true;
    securityStatus("Scan the code with your authenticator app, then enter the 6 digits it shows.");
    el("totp-code").focus();
  } catch (err) {
    securityStatus(err.message);
  }
}

async function confirmTotpSetup() {
  const code = el("totp-code").value.trim();
  if (!code) {
    securityStatus("Enter the code your authenticator app is showing.");
    return;
  }
  try {
    const out = await api("/api/v1/mfa/totp/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    el("totp-setup").hidden = true;
    renderRecoveryCodes(el("profile-recovery-codes"), out.recovery_codes || []);
    el("recovery-codes-box").hidden = false;
    securityStatus("Two-factor authentication is on. Save the recovery codes below.");
    await loadSecurityPage();
  } catch (err) {
    securityStatus(err.message);
  }
}

async function disableTotp() {
  const password = prompt("Confirm your password to turn off two-factor authentication:");
  if (!password) return;
  try {
    await api("/api/v1/mfa/totp/disable", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    el("recovery-codes-box").hidden = true;
    securityStatus("Two-factor authentication is off.");
    await loadSecurityPage();
  } catch (err) {
    securityStatus(err.message);
  }
}

async function regenerateRecoveryCodes() {
  if (!confirm("Generate a new set of recovery codes? Your existing codes stop working immediately.")) return;
  try {
    const out = await api("/api/v1/mfa/recovery-codes", { method: "POST" });
    renderRecoveryCodes(el("profile-recovery-codes"), out.recovery_codes || []);
    el("recovery-codes-box").hidden = false;
    securityStatus("New recovery codes generated — save them now.");
    await loadSecurityPage();
  } catch (err) {
    securityStatus(err.message);
  }
}

async function registerPasskey() {
  const name = el("passkey-name").value.trim() || "This device";
  if (!passkeysAvailable()) {
    securityStatus("This browser can't register passkeys here — they require an HTTPS connection.");
    return;
  }
  try {
    securityStatus("Follow your browser's prompt…");
    const start = await api("/api/v1/mfa/passkeys", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    const credential = await navigator.credentials.create({
      publicKey: decodeCreationOptions(start.options),
    });
    if (!credential) throw new Error("No passkey was created.");

    await api("/api/v1/mfa/passkeys/finish", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: start.challenge_id,
        name,
        credential: encodeAttestation(credential),
      }),
    });
    el("passkey-name").value = "";
    securityStatus(`Passkey "${name}" registered.`);
    await loadSecurityPage();
  } catch (err) {
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      securityStatus("Passkey registration was cancelled.");
    } else if (err && err.name === "InvalidStateError") {
      securityStatus("This device already has a passkey registered for your account.");
    } else {
      securityStatus(err.message || "Passkey registration failed.");
    }
  }
}

async function loadUsersTable() {
  const rows = await api("/api/v1/users");
  const tbody = el("users-tbody");
  tbody.innerHTML = "";
  rows.forEach((u) => {
    const tr = document.createElement("tr");
    const tdUser = document.createElement("td");
    tdUser.textContent = u.username;
    const tdEmail = document.createElement("td");
    const emailInput = document.createElement("input");
    emailInput.type = "email";
    emailInput.value = u.email || "";
    emailInput.placeholder = "none";
    tdEmail.appendChild(emailInput);
    const tdMfa = document.createElement("td");
    tdMfa.textContent = u.totp_enabled ? "On" : "Off";
    const tdRole = document.createElement("td");
    const roleSelect = document.createElement("select");
    ["full_admin", "ssh_admin", "tls_admin", "auditor"].forEach((r) => {
      const o = document.createElement("option");
      o.value = r;
      o.textContent = r;
      if (u.role === r) o.selected = true;
      roleSelect.appendChild(o);
    });
    tdRole.appendChild(roleSelect);
    const tdCreated = document.createElement("td");
    tdCreated.textContent = new Date(u.created_at).toLocaleString();
    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";

    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "Save";
    save.addEventListener("click", async () => {
      try {
        if (roleSelect.value !== u.role) {
          await api(`/api/v1/users/${u.id}/role`, {
            method: "PATCH",
            body: JSON.stringify({ role: roleSelect.value }),
          });
        }
        if ((emailInput.value || "").trim() !== (u.email || "")) {
          await api(`/api/v1/users/${u.id}/email`, {
            method: "PATCH",
            body: JSON.stringify({ email: emailInput.value.trim() }),
          });
        }
        el("users-output").textContent = `Saved changes for ${u.username}.`;
        await loadUsersTable();
      } catch (err) {
        el("users-output").textContent = err.message;
      }
    });

    const resetPwd = document.createElement("button");
    resetPwd.type = "button";
    resetPwd.textContent = "Set password";
    resetPwd.addEventListener("click", async () => {
      const p = prompt(`New password for ${u.username} (min 12 chars):`);
      if (!p) return;
      try {
        await api(`/api/v1/users/${u.id}/password`, {
          method: "POST",
          body: JSON.stringify({ new_password: p }),
        });
        el("users-output").textContent = "Password set.";
      } catch (err) {
        el("users-output").textContent = err.message;
      }
    });

    // Works without SMTP: the admin hands the one-time link over themselves.
    const resetLink = document.createElement("button");
    resetLink.type = "button";
    resetLink.textContent = "Reset link";
    resetLink.addEventListener("click", async () => {
      try {
        const out = await api(`/api/v1/users/${u.id}/reset-link`, { method: "POST" });
        const link = out.url || `${window.location.origin}${out.path}`;
        el("users-output").textContent =
          `One-time reset link for ${u.username} (valid ${out.valid_minutes} minutes): ${link}`;
        await navigator.clipboard.writeText(link).catch(() => {});
      } catch (err) {
        el("users-output").textContent = err.message;
      }
    });

    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete user ${u.username}?`)) return;
      await api(`/api/v1/users/${u.id}`, { method: "DELETE" });
      await loadUsersTable();
    });

    actions.append(save, resetPwd, resetLink, del);
    tdActions.appendChild(actions);
    tr.append(tdUser, tdEmail, tdRole, tdMfa, tdCreated, tdActions);
    tbody.appendChild(tr);
  });
}

// ---- API Tokens ----

async function loadTokenScopeChoices() {
  const container = el("token-scopes");
  if (!container || container.childElementCount) return; // load once
  let data;
  try {
    data = await api("/api/v1/tokens/scopes");
  } catch (err) {
    container.textContent = `Unable to load scopes: ${err.message}`;
    return;
  }
  const descriptions = data.descriptions || {};
  (data.scopes || []).forEach((scope) => {
    const label = document.createElement("label");
    label.className = "checkbox-row";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = scope;
    cb.className = "token-scope-cb";
    const span = document.createElement("span");
    span.innerHTML = `<code>${scope}</code> — ${descriptions[scope] || ""}`;
    label.append(cb, span);
    container.appendChild(label);
  });
  if (!(data.scopes || []).length) {
    container.textContent = "Your role cannot grant any token scopes.";
  }
}

async function loadTokensTable() {
  const rows = await api("/api/v1/tokens");
  const tbody = el("tokens-tbody");
  tbody.innerHTML = "";
  const fmt = (v) => (v ? new Date(v).toLocaleString() : "—");
  rows.forEach((t) => {
    const tr = document.createElement("tr");
    const cells = [
      t.name,
      t.token_prefix + "…",
      (t.scopes || []).join(" "),
      t.owner_username,
      fmt(t.created_at),
      t.expires_at ? fmt(t.expires_at) : "never",
      fmt(t.last_used_at),
      t.is_revoked ? "revoked" : "active",
    ];
    cells.forEach((c) => {
      const td = document.createElement("td");
      td.textContent = c;
      tr.appendChild(td);
    });
    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (!t.is_revoked) {
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke";
      revoke.addEventListener("click", async () => {
        if (!confirm(`Revoke token "${t.name}"? Anything using it will stop working.`)) return;
        await api(`/api/v1/tokens/${t.id}/revoke`, { method: "POST" });
        await loadTokensTable();
        el("tokens-output").textContent = "Token revoked";
      });
      actions.appendChild(revoke);
    }
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete token "${t.name}"?`)) return;
      await api(`/api/v1/tokens/${t.id}`, { method: "DELETE" });
      await loadTokensTable();
      el("tokens-output").textContent = "Token deleted";
    });
    actions.appendChild(del);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  });
}

async function loadTokensPage() {
  await loadTokenScopeChoices();
  await loadTokensTable();
}

// ---- SSH Certificates ----

async function renderSshCaList() {
  const container = el("ssh-ca-list");
  container.innerHTML = "";
  let cas;
  try {
    cas = await api("/api/v1/ssh/cas");
  } catch (err) {
    container.textContent = `Unable to load CAs: ${err.message}`;
    return;
  }
  cas.forEach((ca) => {
    const box = document.createElement("div");
    box.className = "token-reveal-box";
    const title = document.createElement("p");
    title.innerHTML = `<strong>${ca.name}</strong> (${ca.ca_type} CA) — <code>${ca.fingerprint_sha256}</code>`;
    const row = document.createElement("div");
    row.className = "token-reveal-row";
    const code = document.createElement("code");
    code.className = "token-value";
    code.textContent = ca.public_key;
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", async () => {
      const ok = await copyTextToClipboard(ca.public_key);
      flashCopyFeedback(copyBtn, ok);
      el("ssh-certs-output").textContent = ok
        ? "CA public key copied."
        : "Copy failed - select the key and copy it manually.";
    });
    const dl = document.createElement("button");
    dl.type = "button";
    dl.textContent = "Download";
    dl.addEventListener("click", () => downloadApi(`/api/v1/ssh/cas/${ca.id}/public`, `akamana_ssh_${ca.ca_type}_ca.pub`).catch((err) => (el("ssh-certs-output").textContent = err.message)));
    row.append(code, copyBtn, dl);
    const install = document.createElement("p");
    install.className = "hint";
    if (ca.ca_type === "user") {
      install.innerHTML = `Install on servers: add <code>TrustedUserCAKeys /etc/ssh/akamana_user_ca.pub</code> to <code>sshd_config</code>, then place this file there.`;
    } else {
      install.innerHTML = `Install on clients: add <code>@cert-authority *.example.com ${ca.public_key.split(" ").slice(0, 2).join(" ")}</code> to <code>~/.ssh/known_hosts</code>.`;
    }
    box.append(title, row, install);
    container.appendChild(box);
  });
}

async function loadSshCertKeyChoices() {
  const sel = el("ssh-cert-existing");
  sel.innerHTML = "";
  try {
    const data = await api("/api/v1/certificates/ssh?limit=1000");
    const items = asItems(data);
    items.forEach((k) => {
      const o = document.createElement("option");
      o.value = k.id;
      o.textContent = `${k.machine_name || k.ssh_username || "key"} — ${k.fingerprint_sha256 || k.id}`;
      sel.appendChild(o);
    });
  } catch (_) {}
}

function syncSshCertSourceRows() {
  const src = el("ssh-cert-source").value;
  el("ssh-cert-gen-comment-row").hidden = src !== "generate";
  el("ssh-cert-existing-row").hidden = src !== "existing";
  el("ssh-cert-paste-row").hidden = src !== "paste";
}

function syncSshCertTypeHint() {
  const t = el("ssh-cert-type").value;
  el("ssh-cert-principals-hint").textContent =
    t === "host"
      ? "Hostnames / FQDNs this certificate is valid for."
      : "Usernames the certificate may log in as.";
}

async function loadSshCertsTable() {
  const data = await api("/api/v1/ssh/certificates?limit=1000");
  const items = asItems(data);
  const tbody = el("ssh-certs-tbody");
  tbody.innerHTML = "";
  items.forEach((c) => {
    const tr = document.createElement("tr");
    const cells = [
      c.key_id,
      c.cert_type,
      (c.principals || []).join(", "),
      c.valid_to ? new Date(c.valid_to).toLocaleString() : "—",
      c.is_revoked ? "revoked" : "active",
    ];
    cells.forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const view = document.createElement("button");
    view.type = "button";
    view.textContent = "View";
    view.addEventListener("click", async () => {
      const detail = await api(`/api/v1/ssh/certificates/${c.id}`);
      el("ssh-cert-result-cert").textContent = detail.certificate;
      el("ssh-cert-result").hidden = false;
      const hasPriv = Boolean(detail.private_key);
      el("ssh-cert-result-private-wrap").hidden = !hasPriv;
      if (hasPriv) el("ssh-cert-result-private").textContent = detail.private_key;
    });
    actions.appendChild(view);
    if (!c.is_revoked) {
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke";
      revoke.addEventListener("click", async () => {
        if (!confirm(`Revoke certificate "${c.key_id}"?`)) return;
        await api(`/api/v1/ssh/certificates/${c.id}/revoke`, { method: "POST" });
        await loadSshCertsTable();
      });
      actions.appendChild(revoke);
    }
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete certificate "${c.key_id}"?`)) return;
      await api(`/api/v1/ssh/certificates/${c.id}`, { method: "DELETE" });
      await loadSshCertsTable();
    });
    actions.appendChild(del);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  });
}

async function loadSshCertsPage() {
  syncSshCertSourceRows();
  syncSshCertTypeHint();
  await renderSshCaList();
  await loadSshCertKeyChoices();
  await loadSshCertsTable();
}

// ---- Developer API docs ----

function renderApiDocs() {
  const container = el("api-docs-content");
  if (!container || container.dataset.rendered === "1") return;
  container.dataset.rendered = "1";
  const origin = window.location.origin;
  container.innerHTML = `
    <div class="explain">
      <p>Akamana exposes a REST API so scripts, CI pipelines, and deployment tools can request certificates and keys without a browser. Authenticate with an <strong>API token</strong> (create one on the <strong>API Tokens</strong> page) sent as a bearer header. Every token is limited to the <em>scopes</em> you granted it.</p>
    </div>
    <p>Machine-readable spec (OpenAPI 3.1): <a href="/api/v1/openapi.json" target="_blank" rel="noopener"><code>/api/v1/openapi.json</code></a></p>
    <h3>Scopes</h3>
    <table>
      <thead><tr><th>Scope</th><th>Grants</th></tr></thead>
      <tbody>
        <tr><td><code>tls:issue</code></td><td>Issue TLS certificates/keys (<code>POST /keys/tls</code>)</td></tr>
        <tr><td><code>tls:read</code></td><td>Read TLS certs and the CRL</td></tr>
        <tr><td><code>ssh:issue</code></td><td>Generate SSH keypairs (<code>POST /keys/ssh</code>)</td></tr>
        <tr><td><code>ssh:sign</code></td><td>Sign SSH certificates (<code>POST /ssh/certificates</code>)</td></tr>
        <tr><td><code>ssh:read</code></td><td>Read SSH keys/certificates</td></tr>
        <tr><td><code>ca:read</code></td><td>Read CA public keys</td></tr>
      </tbody>
    </table>
    <h3>Examples</h3>
    <p>Issue a TLS certificate:</p>
    <pre class="code-block">curl -s -X POST ${origin}/api/v1/keys/tls \\
  -H "Authorization: Bearer ezk_YOURTOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"common_name":"web01.example.com","valid_days":365,"purpose":"server"}'</pre>
    <p>Generate an SSH keypair:</p>
    <pre class="code-block">curl -s -X POST ${origin}/api/v1/keys/ssh \\
  -H "Authorization: Bearer ezk_YOURTOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"comment":"deploy@web01","valid_days":365}'</pre>
    <p>Sign an SSH user certificate (generating a fresh key):</p>
    <pre class="code-block">curl -s -X POST ${origin}/api/v1/ssh/certificates \\
  -H "Authorization: Bearer ezk_YOURTOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"cert_type":"user","key_id":"alice-login","principals":["alice"],"valid_days":30,"generate":{"comment":"alice@laptop"}}'</pre>
    <p>Fetch the SSH CA public keys to distribute to hosts:</p>
    <pre class="code-block">curl -s ${origin}/api/v1/ssh/cas \\
  -H "Authorization: Bearer ezk_YOURTOKEN"</pre>
  `;
}

async function runCertAction(label, fn) {
  try {
    el("cert-action-status").textContent = `${label}...`;
    await fn();
    el("cert-action-status").textContent = `${label} completed.`;
    await refreshAll();
    if (state.selected) {
      if (state.selected.is_root_row) {
        await loadSelectedDetail();
        return;
      }
      const stillThere = (state.tab === "tls" ? state.tls : state.ssh).find((x) => x.id === state.selected.id);
      if (stillThere) {
        state.selected = stillThere;
        await loadSelectedDetail();
      } else {
        state.selected = null;
        state.selectedDetail = null;
        renderList();
        renderDetails();
      }
    }
  } catch (err) {
    el("cert-action-status").textContent = `${label} failed: ${err.message}`;
  }
}

function populateSelect(node, items, valueKey, labelFn, blankLabel) {
  if (!node) return;
  const prev = node.value;
  node.innerHTML = "";
  if (blankLabel !== undefined) {
    const o = document.createElement("option");
    o.value = "";
    o.textContent = blankLabel;
    node.appendChild(o);
  }
  items.forEach((it) => {
    const o = document.createElement("option");
    o.value = String(it[valueKey]);
    o.textContent = labelFn(it);
    node.appendChild(o);
  });
  if (prev) node.value = prev;
}

// ---- Applications ----

async function loadApplicationsPage() {
  state.applications = asItems(await api("/api/v1/applications"));
  const tbody = el("applications-tbody");
  tbody.innerHTML = "";
  state.applications.forEach((app) => {
    const tr = document.createElement("tr");
    const cells = [app.name, app.slug, (app.expected_cert_format || "—").toUpperCase(), app.default_cert_path || "—", app.default_key_path || "—", app.default_reload_command || "—", app.is_builtin ? "Yes" : "No"];
    cells.forEach((c) => {
      const td = document.createElement("td");
      td.textContent = c;
      tr.appendChild(td);
    });
    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.textContent = "Edit";
    edit.addEventListener("click", () => openAppModal(app));
    actions.appendChild(edit);
    if (!app.is_builtin) {
      const del = document.createElement("button");
      del.type = "button";
      del.textContent = "Delete";
      del.addEventListener("click", async () => {
        if (!confirm(`Delete application ${app.name}?`)) return;
        try {
          await api(`/api/v1/applications/${app.id}`, { method: "DELETE" });
          await loadApplicationsPage();
        } catch (err) {
          el("applications-output").textContent = err.message;
        }
      });
      actions.appendChild(del);
    }
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  });
}

function openAppModal(app) {
  el("app-error").textContent = "";
  el("app-modal-title").textContent = app ? "Edit application" : "Add application";
  el("app-id").value = app ? app.id : "";
  el("app-name").value = app ? app.name : "";
  el("app-slug").value = app ? app.slug : "";
  el("app-cert-path").value = app ? (app.default_cert_path || "") : "";
  el("app-key-path").value = app ? (app.default_key_path || "") : "";
  el("app-chain-path").value = app ? (app.default_chain_path || "") : "";
  el("app-config-dir").value = app ? (app.default_config_dir || "") : "";
  el("app-reload").value = app ? (app.default_reload_command || "") : "";
  el("app-config-example").value = app ? (app.config_example || "") : "";
  el("app-notes").value = app ? (app.notes || "") : "";
  el("app-cert-format").value = app ? (app.expected_cert_format || "") : "";
  el("app-modal").showModal();
}

async function saveApplication() {
  const id = el("app-id").value;
  const body = {
    slug: el("app-slug").value,
    name: el("app-name").value,
    default_cert_path: el("app-cert-path").value || null,
    default_key_path: el("app-key-path").value || null,
    default_chain_path: el("app-chain-path").value || null,
    default_config_dir: el("app-config-dir").value || null,
    default_reload_command: el("app-reload").value || null,
    config_example: el("app-config-example").value || null,
    notes: el("app-notes").value || null,
    expected_cert_format: el("app-cert-format").value || null,
  };
  const path = id ? `/api/v1/applications/${id}` : "/api/v1/applications";
  await api(path, { method: id ? "PATCH" : "POST", body: JSON.stringify(body) });
  el("app-modal").close();
  await loadApplicationsPage();
}

// ---- Credentials ----

async function loadCredentialsPage() {
  state.credentials = asItems(await api("/api/v1/credentials"));
  const tbody = el("credentials-tbody");
  tbody.innerHTML = "";
  state.credentials.forEach((c) => {
    const tr = document.createElement("tr");
    [c.name, c.kind, c.username || "—", c.has_secret ? "set" : "—", c.has_ssh_private_key ? "set" : "—"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdActions = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.textContent = "Edit";
    edit.addEventListener("click", () => openCredModal(c));
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete credential ${c.name}?`)) return;
      try {
        await api(`/api/v1/credentials/${c.id}`, { method: "DELETE" });
        await loadCredentialsPage();
      } catch (err) {
        el("credentials-output").textContent = err.message;
      }
    });
    actions.append(edit, del);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  });
}

function openCredModal(cred) {
  el("cred-error").textContent = "";
  el("cred-modal-title").textContent = cred ? "Edit credential" : "Add credential";
  el("cred-edit-hint").hidden = !cred;
  el("cred-id").value = cred ? cred.id : "";
  el("cred-name").value = cred ? cred.name : "";
  el("cred-kind").value = cred ? cred.kind : "ssh_key";
  el("cred-kind").disabled = Boolean(cred);
  el("cred-username").value = cred ? (cred.username || "") : "";
  el("cred-secret").value = "";
  el("cred-ssh-key").value = "";
  el("cred-ssh-pass").value = "";
  el("cred-notes").value = cred ? (cred.notes || "") : "";
  const sshSource = el("cred-ssh-source");
  sshSource.innerHTML = '<option value="">— paste a key manually below —</option>';
  (state.ssh || [])
    .filter((k) => !k.is_revoked)
    .forEach((k) => {
      const o = document.createElement("option");
      o.value = k.id;
      const fp = (k.fingerprint_sha256 || "").slice(0, 20);
      o.textContent = `${k.ssh_username || k.machine_name || "ssh key"} (${k.algorithm || "ed25519"} ${fp})`;
      sshSource.appendChild(o);
    });
  sshSource.value = "";
  el("cred-modal").showModal();
}

async function saveCredential() {
  const id = el("cred-id").value;
  const base = {
    name: el("cred-name").value,
    username: el("cred-username").value || null,
    notes: el("cred-notes").value || null,
  };
  const secret = el("cred-secret").value;
  const sshKey = el("cred-ssh-key").value;
  const sshPass = el("cred-ssh-pass").value;
  const sshKeyId = el("cred-ssh-source").value;
  if (secret) base.secret = secret;
  if (sshKeyId) {
    base.ssh_key_id = sshKeyId;
  } else if (sshKey) {
    base.ssh_private_key = sshKey;
  }
  if (sshPass) base.ssh_passphrase = sshPass;
  let path = "/api/v1/credentials";
  let method = "POST";
  if (id) {
    path = `/api/v1/credentials/${id}`;
    method = "PATCH";
  } else {
    base.kind = el("cred-kind").value;
  }
  await api(path, { method, body: JSON.stringify(base) });
  el("cred-modal").close();
  await loadCredentialsPage();
}

// ---- Hosts inventory ----

async function loadHostsPage() {
  state.machines = asItems(await api("/api/v1/machines"));
  state.applications = asItems(await api("/api/v1/applications"));
  state.credentials = asItems(await api("/api/v1/credentials").catch(() => ({ items: [] })));
  el("host-detail-panel").hidden = true;
  renderHostsTable();
}

function renderHostsTable() {
  const tbody = el("hosts-tbody");
  tbody.innerHTML = "";
  if (!state.machines.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "hint";
    td.textContent = 'No hosts yet. Click "Add host" to register one.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  state.machines.forEach((m) => {
    const tr = document.createElement("tr");
    [m.hostname, m.ip_address, m.os_type || "—", m.environment, m.monitor_only ? "Monitor-only" : "Managed"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdA = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const manage = document.createElement("button");
    manage.type = "button";
    manage.textContent = "Manage";
    manage.addEventListener("click", () => openHostDetail(m.id));
    const edit = document.createElement("button");
    edit.type = "button";
    edit.textContent = "Edit";
    edit.addEventListener("click", () => openHostModal(m));
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete host ${m.hostname}?`)) return;
      try {
        await api(`/api/v1/machines/${m.id}`, { method: "DELETE" });
        await loadHostsPage();
      } catch (err) {
        el("hosts-output").textContent = err.message;
      }
    });
    actions.append(manage, edit, del);
    tdA.appendChild(actions);
    tr.appendChild(tdA);
    tbody.appendChild(tr);
  });
}

async function scanNetwork() {
  const btn = el("scan-network-btn");
  const status = el("scan-status");
  btn.disabled = true;
  status.textContent = "Scanning... this can take several seconds.";
  el("scan-results-table").hidden = true;
  el("scan-add-selected").hidden = true;
  try {
    const body = {
      cidr: el("scan-cidr").value || null,
      port: Number(el("scan-port").value) || 443,
    };
    const res = await api("/api/v1/network/scan", { method: "POST", body: JSON.stringify(body) });
    const items = asItems(res);
    const tbody = el("scan-results-tbody");
    tbody.innerHTML = "";
    if (!items.length) {
      status.textContent = `No hosts answered on ${res.network} (port ${res.port}).`;
      return;
    }
    items.forEach((it) => {
      const tr = document.createElement("tr");
      const tdCheck = document.createElement("td");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "scan-pick";
      cb.dataset.ip = it.ip;
      cb.dataset.hostname = it.hostname || "";
      cb.disabled = Boolean(it.already_known);
      cb.checked = !it.already_known;
      tdCheck.appendChild(cb);
      const cells = [it.ip, it.hostname || "—", String(it.port), it.already_known ? "already added" : "new"];
      tr.appendChild(tdCheck);
      cells.forEach((v) => {
        const td = document.createElement("td");
        td.textContent = v;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    status.textContent = `${res.network}: ${items.length} host(s) responding on port ${res.port}.`;
    el("scan-results-table").hidden = false;
    el("scan-add-selected").hidden = false;
  } catch (err) {
    status.textContent = `Scan failed: ${err.message}`;
  } finally {
    btn.disabled = false;
  }
}

async function addSelectedScanned() {
  const picks = Array.from(document.querySelectorAll(".scan-pick")).filter((c) => c.checked && !c.disabled);
  if (!picks.length) {
    el("scan-status").textContent = "Select at least one new host.";
    return;
  }
  const port = Number(el("scan-port").value) || 443;
  let added = 0;
  const errors = [];
  for (const cb of picks) {
    const ip = cb.dataset.ip;
    const hostname = cb.dataset.hostname || ip;
    try {
      const created = await api("/api/v1/machines", {
        method: "POST",
        body: JSON.stringify({ hostname, ip_address: ip, owner: "lab-ops", environment: "internal-lab" }),
      });
      // Also monitor the port we discovered it on, so it shows up in the table immediately.
      if (created && created.id) {
        await api("/api/v1/machines/monitor/ports", {
          method: "POST",
          body: JSON.stringify({ machine_id: created.id, port }),
        }).catch(() => {});
      }
      added += 1;
      cb.disabled = true;
      cb.checked = false;
    } catch (err) {
      errors.push(`${ip}: ${err.message}`);
    }
  }
  const failureNote = errors.length ? `; ${errors.length} failed (${errors[0]})` : "";
  el("scan-status").textContent = `Added ${added} host(s)${failureNote}.`;
  await loadMachinesPage().catch(() => {});
}

function openHostModal(host) {
  el("host-modal-error").textContent = "";
  el("host-modal-form").reset();
  el("host-modal-id").value = host ? host.id : "";
  el("host-modal-title").textContent = host ? "Edit host" : "Add host";
  if (host) {
    el("host-modal-hostname").value = host.hostname || "";
    el("host-modal-ip").value = host.ip_address || "";
    el("host-modal-os").value = host.os_type || "";
    el("host-modal-owner").value = host.owner || "lab-ops";
    el("host-modal-env").value = host.environment || "internal-lab";
  }
  el("host-modal").showModal();
}

async function openHostDetail(mid) {
  state.selectedHostId = mid;
  const m = state.machines.find((x) => x.id === mid);
  el("host-detail-title").textContent = m ? `Manage ${m.hostname}` : "Manage host";
  el("host-detail-panel").hidden = false;
  populateSelect(el("hc-credential"), state.credentials, "id", (c) => `${c.name} (${c.kind})`, "Select credential");
  populateSelect(el("ha-credential"), state.credentials, "id", (c) => `${c.name} (${c.kind})`, "Host default");
  populateSelect(el("ha-application"), state.applications, "id", (a) => a.name, "Select application");
  await loadHostDetails();
  el("host-detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadHostDetails() {
  const mid = state.selectedHostId;
  if (!mid) {
    el("host-certs").textContent = "Select a host.";
    el("host-cred-tbody").innerHTML = "";
    el("host-app-tbody").innerHTML = "";
    return;
  }
  const machine = state.machines.find((m) => m.id === mid);
  el("host-name").value = machine ? (machine.hostname || "") : "";
  el("host-ip").value = machine ? (machine.ip_address || "") : "";
  el("host-os").value = machine ? (machine.os_type || "") : "";
  el("host-alert-email").value = machine ? (machine.alert_email || "") : "";
  el("host-test-url").value = machine ? (machine.test_url || "") : "";
  el("host-monitor-only").checked = machine ? Boolean(machine.monitor_only) : false;
  if (!state.tls.length && !state.ssh.length) {
    state.tls = asItems(await api("/api/v1/certificates/tls").catch(() => ({ items: [] })));
    state.ssh = asItems(await api("/api/v1/certificates/ssh").catch(() => ({ items: [] })));
  }
  const hostTls = state.tls.filter((t) => t.machine_id === mid);
  const hostSsh = state.ssh.filter((s) => s.machine_id === mid);
  populateSelect(el("ha-cert"), hostTls.concat(state.tls.filter((t) => t.machine_id !== mid && t.cert_level !== "intermediate")), "id", (t) => `${t.common_name}${t.machine_id === mid ? "" : " (unassigned)"}`, "No certificate yet");

  const certsHolder = el("host-certs");
  certsHolder.innerHTML = "";
  if (!hostTls.length && !hostSsh.length) {
    certsHolder.textContent = "No certificates linked to this host yet.";
  } else {
    const ul = document.createElement("ul");
    ul.className = "host-cert-list";
    hostTls.forEach((t) => {
      const li = document.createElement("li");
      const st = certExpiryStatus(t);
      li.innerHTML = `<span class="status-dot dot-${st.cls.replace("st-", "")}"></span>`;
      const span = document.createElement("span");
      span.textContent = `TLS  ${t.common_name} (${t.cert_level || "leaf"}) — ${st.text}`;
      li.appendChild(span);
      ul.appendChild(li);
    });
    hostSsh.forEach((s) => {
      const li = document.createElement("li");
      const st = certExpiryStatus(s);
      li.innerHTML = `<span class="status-dot dot-${st.cls.replace("st-", "")}"></span>`;
      const span = document.createElement("span");
      span.textContent = `SSH  ${s.ssh_username || "user"}@${s.machine_name || "host"} — ${st.text}`;
      li.appendChild(span);
      ul.appendChild(li);
    });
    certsHolder.appendChild(ul);
  }

  state.hostCredentials = asItems(await api(`/api/v1/host-credentials?machine_id=${encodeURIComponent(mid)}`));
  const ctbody = el("host-cred-tbody");
  ctbody.innerHTML = "";
  state.hostCredentials.forEach((hc) => {
    const tr = document.createElement("tr");
    [hc.credential_name, hc.protocol, hc.port || "—", hc.is_default ? "Yes" : "No", hc.last_check_status || "never"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdA = document.createElement("td");
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Unlink";
    del.addEventListener("click", async () => {
      await api(`/api/v1/host-credentials/${hc.id}`, { method: "DELETE" });
      await loadHostDetails();
    });
    tdA.appendChild(del);
    tr.appendChild(tdA);
    ctbody.appendChild(tr);
  });

  state.hostApplications = asItems(await api(`/api/v1/host-applications?machine_id=${encodeURIComponent(mid)}`));
  const atbody = el("host-app-tbody");
  atbody.innerHTML = "";
  state.hostApplications.forEach((ha) => {
    const certName = ha.tls_key_id ? (state.tls.find((t) => t.id === ha.tls_key_id)?.common_name || ha.tls_key_id) : "—";
    const tr = document.createElement("tr");
    [ha.application_name, certName, ha.cert_path || "(app default)", ha.auto_deploy ? "Yes" : "No", ha.last_deploy_status || "never"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdA = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";

    const check = document.createElement("button");
    check.type = "button";
    check.textContent = "Check";
    check.addEventListener("click", () => runDeployAction(ha.id, "check"));

    const deploy = document.createElement("button");
    deploy.type = "button";
    deploy.textContent = "Deploy";
    deploy.addEventListener("click", () => runDeployAction(ha.id, "deploy"));

    const history = document.createElement("button");
    history.type = "button";
    history.textContent = "History";
    history.addEventListener("click", () => loadDeploymentHistory(ha.id));

    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Remove";
    del.addEventListener("click", async () => {
      await api(`/api/v1/host-applications/${ha.id}`, { method: "DELETE" });
      await loadHostDetails();
    });
    actions.append(check, deploy, history, del);
    tdA.appendChild(actions);
    tr.appendChild(tdA);
    atbody.appendChild(tr);
  });

  await loadCertbotConfigs(mid);
}

async function loadCertbotConfigs(mid) {
  const tbody = el("certbot-tbody");
  tbody.innerHTML = "";
  const res = await api(`/api/v1/certbot/configs?machine_id=${encodeURIComponent(mid)}`).catch(() => ({ items: [] }));
  asItems(res).forEach((cb) => {
    const tr = document.createElement("tr");
    const expires = cb.last_not_after ? new Date(cb.last_not_after).toLocaleDateString() : "—";
    const lastRun = cb.last_run_at ? `${cb.last_run_status || "?"} (${new Date(cb.last_run_at).toLocaleDateString()})` : "never";
    [cb.domains, cb.challenge, cb.staging ? "Yes" : "No", cb.auto_renew ? "Yes" : "No", lastRun, expires].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdA = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const run = document.createElement("button");
    run.type = "button";
    run.textContent = "Run now";
    run.addEventListener("click", async () => {
      el("host-deploy-output").textContent = "Running certbot...";
      try {
        const r = await api(`/api/v1/certbot/configs/${cb.id}/run`, { method: "POST" });
        await renderDeploymentJournal(r.job_id);
        await loadCertbotConfigs(mid);
      } catch (err) {
        el("host-deploy-output").textContent = err.message;
      }
    });
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm("Delete this certbot config?")) return;
      await api(`/api/v1/certbot/configs/${cb.id}`, { method: "DELETE" });
      await loadCertbotConfigs(mid);
    });
    actions.append(run, del);
    tdA.appendChild(actions);
    tr.appendChild(tdA);
    tbody.appendChild(tr);
  });
}

async function runDeployAction(hostApplicationId, mode) {
  const out = el("host-deploy-output");
  out.textContent = mode === "check" ? "Running pre-flight checks..." : "Deploying...";
  try {
    const res = await api(`/api/v1/host-applications/${hostApplicationId}/${mode}`, { method: "POST" });
    await renderDeploymentJournal(res.job_id);
    await loadHostDetails();
  } catch (err) {
    out.textContent = err.message;
  }
}

async function loadDeploymentHistory(hostApplicationId) {
  const out = el("host-deploy-output");
  try {
    const res = await api(`/api/v1/host-applications/${hostApplicationId}/deployments`);
    const jobs = asItems(res);
    if (!jobs.length) {
      out.textContent = "No deployment runs yet.";
      return;
    }
    out.innerHTML = "";
    const ul = document.createElement("ul");
    ul.className = "host-cert-list";
    jobs.forEach((j) => {
      const li = document.createElement("li");
      const link = document.createElement("button");
      link.type = "button";
      link.className = "linklike";
      link.textContent = `${j.job_type} — ${j.status} — ${new Date(j.created_at).toLocaleString()}`;
      link.addEventListener("click", () => renderDeploymentJournal(j.id));
      li.appendChild(link);
      ul.appendChild(li);
    });
    out.appendChild(ul);
  } catch (err) {
    out.textContent = err.message;
  }
}

async function renderDeploymentJournal(jobId) {
  const out = el("host-deploy-output");
  const res = await api(`/api/v1/deployments/${jobId}/journal`);
  const job = res.job || {};
  const steps = asItems(res.steps);
  out.innerHTML = "";
  const head = document.createElement("p");
  head.innerHTML = `<strong>${job.job_type || "job"}</strong> — status: <strong>${job.status || "?"}</strong>`;
  out.appendChild(head);
  const table = document.createElement("table");
  table.className = "logs-table";
  table.innerHTML = "<thead><tr><th>Time</th><th>Step</th><th>Status</th><th>Message</th></tr></thead>";
  const tbody = document.createElement("tbody");
  steps.forEach((s) => {
    const tr = document.createElement("tr");
    [new Date(s.created_at).toLocaleTimeString(), s.step, s.status, s.message || ""].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  out.appendChild(table);
}

function bindEvents() {
  el("menu-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const panel = el("main-menu");
    setMainMenuOpen(panel.hidden);
  });
  el("mode-toggle").addEventListener("click", toggleMode);
  el("first-run-create").addEventListener("click", () => el("org-modal").showModal());
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest && e.target.closest(".copy-cmd-btn");
    if (!btn) return;
    const target = el(btn.dataset.copyTarget);
    if (!target) return;
    const ok = await copyTextToClipboard(target.textContent || "");
    flashCopyFeedback(btn, ok);
  });
  document.addEventListener("click", (e) => {
    const panel = el("main-menu");
    if (panel.hidden) return;
    const toggle = el("menu-toggle");
    if (panel.contains(e.target) || toggle.contains(e.target)) return;
    setMainMenuOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setMainMenuOpen(false);
  });
  el("lang-en").addEventListener("click", () => setLang("en"));
  el("lang-fr").addEventListener("click", () => setLang("fr"));
  bindInlineInfoIcons();
  CIPHER_COMPATIBILITY_CONFIG.forEach(({ selectId }) => {
    const node = el(selectId);
    if (!node) return;
    node.addEventListener("change", refreshCipherCompatibilityHints);
  });
  KEY_LENGTH_PAIRS.forEach(([cipherId]) => {
    const node = el(cipherId);
    if (!node) return;
    node.addEventListener("change", applyKeyLengthOptions);
  });

  document.querySelectorAll(".nav-item").forEach((b) => {
    b.addEventListener("click", async () => {
      showPage(b.dataset.page);
      if (b.dataset.page === "logs") await loadLogs();
      if (b.dataset.page === "users") {
        await loadUsersTable();
      }
      if (b.dataset.page === "profile") {
        await loadSecurityPage().catch((err) => securityStatus(err.message));
      }
      if (b.dataset.page === "tokens") {
        await loadTokensPage().catch((err) => (el("tokens-output").textContent = err.message));
      }
      if (b.dataset.page === "api") {
        renderApiDocs();
      }
      if (b.dataset.page === "machines") {
        await loadMachinesPage();
      }
      if (b.dataset.page === "hosts") {
        await loadHostsPage().catch((err) => (el("hosts-output").textContent = err.message));
      }
      if (b.dataset.page === "applications") {
        await loadApplicationsPage().catch((err) => (el("applications-output").textContent = err.message));
      }
      if (b.dataset.page === "credentials") {
        await loadCredentialsPage().catch((err) => (el("credentials-output").textContent = err.message));
      }
      if (b.dataset.page === "deploy") renderDeploy(true);
      if (b.dataset.page === "settings") {
        await loadDefaults();
        await loadMachineMonitorSettings().catch(() => {});
        await loadBackupSettings().catch(() => {});
        await loadBackupRemoteSettings().catch(() => {});
        await loadCrlRemoteSettings().catch(() => {});
        await loadDeployHtmlRemoteSettings().catch(() => {});
        await loadBackupList().catch(() => {});
      }
    });
  });

  el("public-root-select").addEventListener("change", (e) => {
    state.selectedRootId = Number(e.target.value);
    syncRootSelectValues();
    renderDeploy(false);
  });
  el("private-root-select").addEventListener("change", (e) => {
    state.selectedRootId = Number(e.target.value);
    syncRootSelectValues();
    renderDeploy(true);
  });
  el("org-root-select").addEventListener("change", (e) => {
    state.selectedRootId = Number(e.target.value);
    syncRootSelectValues();
    state.selected = null;
    state.selectedDetail = null;
    state.deployGuide = null;
    renderList();
    renderDetails();
  });

  // ---- Sign-in dialog ----
  el("login-open").addEventListener("click", () => openLogin("credentials"));
  el("login-cancel").addEventListener("click", () => el("login-modal").close());
  el("login-modal").addEventListener("close", () => {
    // Never leave a half-finished sign-in behind when the dialog is dismissed.
    if (!state.token) {
      state.auth.mfaToken = null;
      el("login-pass").value = "";
    }
  });

  el("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    submitLogin(e.submitter || el("login-form").querySelector(".auth-primary"));
  });
  el("mfa-form").addEventListener("submit", (e) => {
    e.preventDefault();
    submitMfa(e.submitter || el("mfa-form").querySelector(".auth-primary"));
  });
  el("mfa-enroll-form").addEventListener("submit", (e) => {
    e.preventDefault();
    submitEnrollment(e.submitter || el("mfa-enroll-form").querySelector(".auth-primary"));
  });
  el("forgot-form").addEventListener("submit", (e) => {
    e.preventDefault();
    submitForgot(e.submitter || el("forgot-form").querySelector(".auth-primary"));
  });
  el("reset-form").addEventListener("submit", (e) => {
    e.preventDefault();
    submitReset(e.submitter || el("reset-form").querySelector(".auth-primary"));
  });

  el("forgot-open").addEventListener("click", () => showAuthStep("forgot"));
  document.querySelectorAll("#login-modal .auth-back").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.auth.mfaToken = null;
      showAuthStep("credentials");
    });
  });
  el("passkey-login-btn").addEventListener("click", (e) => loginWithPasskey(e.currentTarget));
  el("auth-copy-codes").addEventListener("click", () =>
    copyRecoveryCodes("auth-recovery-codes", setAuthNotice)
  );
  el("auth-codes-done").addEventListener("click", () => completeLogin());
  el("reset-pass").addEventListener("input", updatePasswordMeter);

  [
    ["login-pass-toggle", "login-pass"],
    ["reset-pass-toggle", "reset-pass"],
  ].forEach(([toggleId, inputId]) => {
    el(toggleId).addEventListener("click", () => {
      const input = el(inputId);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      el(toggleId).textContent = show ? "Hide" : "Show";
      el(toggleId).setAttribute("aria-pressed", String(show));
      el(toggleId).setAttribute("aria-label", show ? "Hide password" : "Show password");
      input.focus();
    });
  });

  // Clear a field's error as soon as the user starts fixing it.
  ["login-user", "login-pass", "mfa-code", "enroll-code", "forgot-identifier", "reset-pass2"].forEach((id) => {
    const node = el(id);
    if (node) node.addEventListener("input", () => setFieldError(id, ""));
  });

  el("logout-btn").addEventListener("click", logout);

  // ---- Profile > sign-in security ----
  el("totp-start-btn").addEventListener("click", startTotpSetup);
  el("totp-confirm-btn").addEventListener("click", confirmTotpSetup);
  el("totp-cancel-btn").addEventListener("click", () => {
    el("totp-setup").hidden = true;
    securityStatus("");
  });
  el("totp-disable-btn").addEventListener("click", disableTotp);
  el("totp-codes-btn").addEventListener("click", regenerateRecoveryCodes);
  el("recovery-copy-btn").addEventListener("click", () =>
    copyRecoveryCodes("profile-recovery-codes", securityStatus)
  );
  el("passkey-add-btn").addEventListener("click", registerPasskey);

  document.querySelectorAll("[data-tab]").forEach((b) => {
    b.addEventListener("click", () => {
      state.tab = b.dataset.tab;
      document.querySelectorAll("[data-tab]").forEach((x) => x.classList.toggle("active", x.dataset.tab === state.tab));
      const tls = state.tab === "tls";
      const isSshCert = state.tab === "sshcert";
      // SSH Certificates is its own panel; the shared list/form workspace is hidden for it.
      el("cert-workspace").hidden = isSshCert;
      el("sshcert-panel").hidden = !isSshCert;
      document.querySelectorAll(".tls-only").forEach((n) => (n.hidden = !tls));
      document.querySelectorAll(".ssh-only").forEach((n) => (n.hidden = tls || isSshCert));
      // A hidden required field still blocks submit in Chrome, so only require CN for TLS.
      el("cf-common-name").required = tls;
      if (isSshCert) {
        loadSshCertsPage().catch((err) => (el("ssh-certs-output").textContent = err.message));
        return;
      }
      state.selected = null;
      state.selectedDetail = null;
      state.deployGuide = null;
      renderList();
      renderDetails();
    });
  });

  el("add-org-btn").addEventListener("click", () => el("org-modal").showModal());
  el("delete-org-btn").addEventListener("click", async () => {
    const root = selectedRoot();
    if (!root) {
      el("cert-action-status").textContent = "No organization/root CA selected.";
      return;
    }
    const prompt = `Delete organization "${root.organization}" and root CA "${root.common_name}"? This also deletes linked TLS certificates/intermediates and CRL entries.`;
    if (!confirm(prompt)) return;
    try {
      el("cert-action-status").textContent = "Deleting organization and root CA...";
      await api(`/api/v1/certificates/root/${root.id}`, { method: "DELETE" });
      state.selected = null;
      state.selectedDetail = null;
      state.deployGuide = null;
      await refreshAll();
      el("cert-action-status").textContent = `Organization "${root.organization}" deleted.`;
    } catch (err) {
      el("cert-action-status").textContent = `Delete failed: ${err.message}`;
    }
  });
  el("org-cancel").addEventListener("click", () => el("org-modal").close());
  el("org-name").addEventListener("input", (e) => {
    if (!el("org-root-cn").value) el("org-root-cn").value = `${e.target.value} Root CA`;
    if (!el("org-int-cn").value) el("org-int-cn").value = `${e.target.value} Intermediate CA`;
  });
  el("org-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/certificates/root", {
        method: "POST",
        body: JSON.stringify({
          organization: f.organization,
          root_common_name: f.root_common_name,
          description: f.description || "",
          root_valid_years: Number(f.root_valid_years),
          country: f.country || null,
          state: f.state || null,
          locality: f.locality || null,
          org_unit: f.org_unit || null,
          root_cipher: f.root_cipher,
          root_key_length: Number(f.root_key_length),
          create_intermediate: f.create_intermediate === "yes",
          intermediate_common_name: f.intermediate_common_name || "",
          intermediate_valid_days: Number(f.intermediate_valid_days || 1825),
          intermediate_cipher: f.intermediate_cipher || "ed25519",
          intermediate_key_length: Number(f.intermediate_key_length || 256),
        }),
      });
      el("org-modal").close();
      el("org-error").textContent = "";
      await loadRoots();
      await refreshAll();
    } catch (err) {
      el("org-error").textContent = err.message;
    }
  });

  el("import-root-btn").addEventListener("click", () => {
    el("import-root-error").textContent = "";
    el("import-root-modal").showModal();
  });
  el("import-root-cancel").addEventListener("click", () => el("import-root-modal").close());
  el("import-root-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target).entries());
    try {
      const res = await api("/api/v1/certificates/root/import", {
        method: "POST",
        body: JSON.stringify({
          organization: f.organization,
          description: f.description || null,
          cert_pem: f.cert_pem,
          private_key_pem: (f.private_key_pem || "").trim() || null,
        }),
      });
      el("import-root-modal").close();
      el("import-root-error").textContent = "";
      e.target.reset();
      await loadRoots();
      await refreshAll();
      el("cert-action-status").textContent = res.can_issue
        ? "Root CA imported. Akamana can issue certificates under it."
        : "Root CA imported as a trust anchor (no private key — cannot issue under it).";
    } catch (err) {
      el("import-root-error").textContent = err.message;
    }
  });

  el("add-cert").addEventListener("click", async () => {
    el("cf-root-id").value = String(state.selectedRootId);
    document.querySelector("#cf-assign-machine-wrap input[name='assign_machine'][value='no']").checked = true;
    el("cf-common-name").required = state.tab === "tls";
    toggleMachineAssignmentUi();
    setPublishDefaultByLevel();
    await fillParentIntermediateOptions();
    el("cert-modal").showModal();
  });
  el("import-cert-btn").addEventListener("click", () => {
    el("im-root-id").value = String(state.selectedRootId);
    document.querySelector("#im-assign-machine-wrap input[name='assign_machine'][value='no']").checked = true;
    toggleImportMachineAssignmentUi();
    el("import-modal").showModal();
  });
  el("import-cancel").addEventListener("click", () => el("import-modal").close());
  el("cert-cancel").addEventListener("click", () => el("cert-modal").close());
  el("cf-hostname").addEventListener("blur", resolveHint);
  el("cf-ip").addEventListener("blur", resolveHint);
  el("cf-root-id").addEventListener("change", fillParentIntermediateOptions);
  el("cf-cert-level").addEventListener("change", () => {
    toggleMachineAssignmentUi();
    setPublishDefaultByLevel();
    fillParentIntermediateOptions();
  });
  document.querySelectorAll("#cf-assign-machine-wrap input[name='assign_machine']").forEach((n) =>
    n.addEventListener("change", toggleMachineAssignmentUi)
  );
  document.querySelectorAll("#im-assign-machine-wrap input[name='assign_machine']").forEach((n) =>
    n.addEventListener("change", toggleImportMachineAssignmentUi)
  );

  el("cert-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    try {
      let machine_id = null;
      const assignMachine = data.assign_machine === "yes" && data.cert_level !== "intermediate";
      if (assignMachine) {
        if (!data.hostname || !data.ip_address) {
          throw new Error("Machine name and IP address are required when assigning a machine.");
        }
        machine_id = await findOrCreateMachine(data);
      }
      if (state.tab === "tls") {
        await api("/api/v1/keys/tls", {
          method: "POST",
          body: JSON.stringify({
            machine_id,
            root_id: Number(data.root_id),
            cert_level: data.cert_level,
            parent_cert_id: data.parent_cert_id || null,
            common_name: data.common_name,
            valid_days: Number(data.valid_days),
            cipher: data.tls_cipher,
            key_length: Number(data.tls_key_length),
            sans: (data.sans || "")
              .split(/[\s,;]+/)
              .map((s) => s.trim())
              .filter(Boolean),
            purpose: data.purpose || "server",
            publish_private_key: data.publish_private_key === "yes",
          }),
        });
      } else {
        await api("/api/v1/keys/ssh", {
          method: "POST",
          body: JSON.stringify({
            machine_id,
            valid_days: Number(data.valid_days),
            comment: data.comment || "ops-user",
            cipher: data.ssh_cipher,
            key_length: Number(data.ssh_key_length),
            publish_private_key: data.publish_private_key === "yes",
          }),
        });
      }
      el("cert-error").textContent = "";
      el("cert-modal").close();
      await refreshAll();
    } catch (err) {
      el("cert-error").textContent = err.message;
    }
  });

  el("act-view").addEventListener("click", async () => {
    if (!state.selected) return;
    await runCertAction("Refreshing certificate details", async () => {
      await loadSelectedDetail();
    });
  });
  el("act-renew").addEventListener("click", async () => {
    if (!state.selected || state.tab !== "tls") return;
    await runCertAction("Renewing certificate", async () => {
      if (state.selected.is_root_row) {
        await api(`/api/v1/certificates/root/${state.selected.root_id}/renew`, { method: "POST" });
        await loadRoots();
        return;
      }
      await api("/api/v1/keys/tls/renew", { method: "POST", body: JSON.stringify({ tls_key_id: state.selected.id, valid_days: 365 }) });
    });
  });
  el("act-auto-renew").addEventListener("click", async () => {
    if (!state.selected || state.tab !== "tls" || state.selected.is_root_row) {
      el("cert-action-status").textContent = "Auto-renew applies to leaf TLS certificates.";
      return;
    }
    const enable = confirm("Enable automatic renewal for this certificate?\n\nOK = enable, Cancel = disable.");
    let days = 30;
    if (enable) {
      const input = prompt("Renew how many days before expiry?", "30");
      if (input === null) return;
      days = Number(input) || 30;
    }
    try {
      await api(`/api/v1/certificates/tls/${state.selected.id}/auto-renew`, {
        method: "PATCH",
        body: JSON.stringify({ auto_renew: enable, renew_days_before: days }),
      });
      el("cert-action-status").textContent = enable
        ? `Auto-renew enabled (${days} days before expiry).`
        : "Auto-renew disabled.";
    } catch (err) {
      el("cert-action-status").textContent = `Auto-renew update failed: ${err.message}`;
    }
  });
  el("act-revoke").addEventListener("click", async () => {
    if (!state.selected) return;
    await runCertAction("Revoking certificate", async () => {
      if (state.selected.is_root_row) {
        await api(`/api/v1/certificates/root/${state.selected.root_id}/revoke`, { method: "POST" });
        return;
      }
      if (state.tab === "tls") {
        await api("/api/v1/crl/revoke", { method: "POST", body: JSON.stringify({ tls_key_id: state.selected.id, reason: "manual revocation" }) });
      } else {
        await api(`/api/v1/keys/ssh/revoke/${state.selected.id}`, { method: "POST" });
      }
    });
  });
  el("act-delete").addEventListener("click", async () => {
    if (!state.selected) return;
    if (state.selected.is_root_row) return;
    const path = state.tab === "tls" ? `/api/v1/certificates/tls/${state.selected.id}` : `/api/v1/certificates/ssh/${state.selected.id}`;
    await runCertAction("Deleting certificate", async () => {
      await api(path, { method: "DELETE" });
      state.selected = null;
      state.selectedDetail = null;
    });
  });
  el("act-publish").addEventListener("click", async () => {
    if (!state.selected) return;
    if (state.selected.is_root_row) return;
    const path = state.tab === "tls"
      ? `/api/v1/certificates/tls/${state.selected.id}/publish-key`
      : `/api/v1/certificates/ssh/${state.selected.id}/publish-key`;
    await runCertAction("Publishing private key export", async () => {
      await api(path, { method: "PATCH", body: JSON.stringify({ allow_private_key_export: true }) });
    });
  });
  el("act-export-public").addEventListener("click", async () => {
    if (!state.selected || state.selected.is_root_row) return;
    const path = state.tab === "tls"
      ? `/api/v1/certificates/tls/${state.selected.id}/export/public`
      : `/api/v1/certificates/ssh/${state.selected.id}/export/public`;
    await runCertAction("Downloading public certificate/key", async () => {
      await downloadApi(path, `${state.selected.id}-public.txt`);
    });
  });
  el("act-export-private").addEventListener("click", async () => {
    if (!state.selected || state.selected.is_root_row) return;
    const path = state.tab === "tls"
      ? `/api/v1/certificates/tls/${state.selected.id}/export/private`
      : `/api/v1/certificates/ssh/${state.selected.id}/export/private`;
    await runCertAction("Downloading private key", async () => {
      await downloadApi(path, `${state.selected.id}-private.txt`);
    });
  });
  el("act-export-format-btn").addEventListener("click", async () => {
    if (!state.selected || state.selected.is_root_row || state.tab !== "tls") return;
    const fmt = el("act-export-format").value;
    let path = `/api/v1/certificates/tls/${state.selected.id}/export?format=${fmt}`;
    if (fmt === "pkcs12") {
      const pw = prompt("Password to protect the .pfx (blank = none):") || "";
      path += `&password=${encodeURIComponent(pw)}`;
    }
    const ext = fmt === "pkcs12" ? "pfx" : fmt;
    await runCertAction(`Exporting certificate (${fmt})`, async () => {
      await downloadApi(path, `${state.selected.id}.${ext}`);
    });
  });

  el("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    const out = await api("/api/v1/settings/defaults", {
      method: "PUT",
      body: JSON.stringify({
        default_tls_cipher: d.default_tls_cipher,
        default_tls_key_length: Number(d.default_tls_key_length),
        default_ssh_cipher: d.default_ssh_cipher,
        default_ssh_key_length: Number(d.default_ssh_key_length),
        cert_owners_json: JSON.stringify(state.owners),
        cert_environments_json: JSON.stringify(state.environments),
        public_base_url: el("public_base_url").value || "",
        crl_base_url: el("crl_base_url").value || "",
      }),
    });
    state.defaults = { ...(state.defaults || {}), public_base_url: el("public_base_url").value || "", crl_base_url: el("crl_base_url").value || "" };
    renderObjectAsTable(el("settings-output"), out);
  });
  el("machine-monitor-settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    const out = await api("/api/v1/settings/machine-monitor", {
      method: "PUT",
      body: JSON.stringify({
        monitor_enabled: d.monitor_enabled === "yes",
        frequency_hours: Number(d.frequency_hours || 24),
        default_ports_csv: d.default_ports_csv || "443,8443",
        alert_webhook_url: d.alert_webhook_url || "",
        alert_email_to: d.alert_email_to || "",
        alert_cooldown_hours: Number(d.alert_cooldown_hours || 24),
      }),
    });
    renderObjectAsTable(el("machine-monitor-settings-output"), out);
    await loadMachineMonitorSettings().catch(() => {});
  });

  el("backup-settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/settings/backup", {
        method: "PUT",
        body: JSON.stringify({
          enabled: d.backup_enabled === "yes",
          frequency_hours: Number(d.frequency_hours || 24),
          retention: Number(d.retention || 5),
          skip_unchanged: d.backup_skip === "yes",
          encryption_mode: d.backup_encryption_mode || "none",
          passphrase: (d.passphrase || "").trim() || null,
        }),
      });
      el("backup-passphrase").value = "";
      el("backup-output").textContent = "Backup settings saved.";
      await loadBackupSettings().catch(() => {});
    } catch (err) {
      el("backup-output").textContent = err.message;
    }
  });
  el("backup-dest-type").addEventListener("change", syncBackupDestRows);
  document.querySelectorAll("input[name='sftp_auth']").forEach((r) => r.addEventListener("change", syncBackupDestRows));
  el("backup-remote-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/settings/backup/remote", {
        method: "PUT",
        body: JSON.stringify({
          dest_type: d.dest_type || "local",
          remote_path: d.remote_path || null,
          remote_retention: Number(d.remote_retention || 7),
          sftp_host: d.sftp_host || null,
          sftp_port: Number(d.sftp_port || 22),
          sftp_user: d.sftp_user || null,
          sftp_auth: d.sftp_auth || "password",
          sftp_remote_dir: d.sftp_remote_dir || null,
          sftp_password: (d.sftp_password || "").trim() || null,
          sftp_private_key: (d.sftp_private_key || "").trim() || null,
          sftp_passphrase: (d.sftp_passphrase || "").trim() || null,
        }),
      });
      el("backup-sftp-password").value = "";
      el("backup-sftp-key").value = "";
      el("backup-sftp-passphrase").value = "";
      el("backup-remote-status").textContent = "Destination saved.";
      await loadBackupRemoteSettings().catch(() => {});
    } catch (err) {
      el("backup-remote-status").textContent = err.message;
    }
  });
  el("backup-remote-test").addEventListener("click", async () => {
    el("backup-remote-status").textContent = "Testing…";
    try {
      const r = await api("/api/v1/backup/remote/test", { method: "POST" });
      el("backup-remote-status").textContent = `✓ ${r.detail}`;
    } catch (err) {
      el("backup-remote-status").textContent = `✗ ${err.message}`;
    }
  });
  el("crl-dest-type").addEventListener("change", syncCrlDestRows);
  document.querySelectorAll("input[name='crl_sftp_auth']").forEach((r) => r.addEventListener("change", syncCrlDestRows));
  el("crl-remote-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/settings/crl/remote", {
        method: "PUT",
        body: JSON.stringify({
          dest_type: d.dest_type || "local",
          remote_path: d.remote_path || null,
          sftp_host: d.sftp_host || null,
          sftp_port: Number(d.sftp_port || 22),
          sftp_user: d.sftp_user || null,
          sftp_auth: d.crl_sftp_auth || "password",
          sftp_remote_dir: d.sftp_remote_dir || null,
          sftp_password: (d.sftp_password || "").trim() || null,
          sftp_private_key: (d.sftp_private_key || "").trim() || null,
          sftp_passphrase: (d.sftp_passphrase || "").trim() || null,
        }),
      });
      el("crl-sftp-password").value = "";
      el("crl-sftp-key").value = "";
      el("crl-sftp-passphrase").value = "";
      el("crl-remote-status").textContent = "CRL destination saved.";
      await loadCrlRemoteSettings().catch(() => {});
    } catch (err) {
      el("crl-remote-status").textContent = err.message;
    }
  });
  el("crl-remote-test").addEventListener("click", async () => {
    el("crl-remote-status").textContent = "Testing…";
    try {
      const r = await api("/api/v1/crl/remote/test", { method: "POST" });
      el("crl-remote-status").textContent = `✓ ${r.detail}`;
    } catch (err) {
      el("crl-remote-status").textContent = `✗ ${err.message}`;
    }
  });
  el("crl-publish-now").addEventListener("click", async () => {
    el("crl-remote-status").textContent = "Publishing…";
    try {
      const r = await api("/api/v1/crl/publish", { method: "POST" });
      el("crl-remote-status").textContent = r.published && r.published.length
        ? `✓ Published: ${r.published.join(", ")}`
        : "✓ CRLs regenerated (no upload destination configured).";
    } catch (err) {
      el("crl-remote-status").textContent = `✗ ${err.message}`;
    }
  });
  el("deployhtml-dest-type").addEventListener("change", syncDeployHtmlDestRows);
  document.querySelectorAll("input[name='deployhtml_sftp_auth']").forEach((r) => r.addEventListener("change", syncDeployHtmlDestRows));
  el("deployhtml-remote-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/settings/deploy-html/remote", {
        method: "PUT",
        body: JSON.stringify({
          dest_type: d.dest_type || "local",
          remote_path: d.remote_path || null,
          sftp_host: d.sftp_host || null,
          sftp_port: Number(d.sftp_port || 22),
          sftp_user: d.sftp_user || null,
          sftp_auth: d.deployhtml_sftp_auth || "password",
          sftp_remote_dir: d.sftp_remote_dir || null,
          sftp_password: (d.sftp_password || "").trim() || null,
          sftp_private_key: (d.sftp_private_key || "").trim() || null,
          sftp_passphrase: (d.sftp_passphrase || "").trim() || null,
        }),
      });
      el("deployhtml-sftp-password").value = "";
      el("deployhtml-sftp-key").value = "";
      el("deployhtml-sftp-passphrase").value = "";
      el("deployhtml-status").textContent = "Destination saved.";
      await loadDeployHtmlRemoteSettings().catch(() => {});
    } catch (err) {
      el("deployhtml-status").textContent = err.message;
    }
  });
  el("deployhtml-preview").addEventListener("click", async () => {
    el("deployhtml-status").textContent = "Generating preview…";
    try {
      const res = await fetch("/api/v1/deploy-html/preview", { headers: { Authorization: `Bearer ${state.token}` } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const html = await res.text();
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      window.open(url, "_blank");
      el("deployhtml-status").textContent = "Preview opened in a new tab.";
    } catch (err) {
      el("deployhtml-status").textContent = `Preview failed: ${err.message}`;
    }
  });
  el("deployhtml-test").addEventListener("click", async () => {
    el("deployhtml-status").textContent = "Testing…";
    try {
      const r = await api("/api/v1/deploy-html/remote/test", { method: "POST" });
      el("deployhtml-status").textContent = `✓ ${r.detail}`;
    } catch (err) {
      el("deployhtml-status").textContent = `✗ ${err.message}`;
    }
  });
  el("deployhtml-publish").addEventListener("click", async () => {
    el("deployhtml-status").textContent = "Publishing…";
    try {
      const r = await api("/api/v1/deploy-html/publish", { method: "POST" });
      el("deployhtml-status").textContent = `✓ Published: ${r.published}`;
    } catch (err) {
      el("deployhtml-status").textContent = `✗ ${err.message}`;
    }
  });
  document.querySelectorAll("input[name='backup_encryption_mode']").forEach((r) => r.addEventListener("change", syncBackupEncRows));
  el("backup-recipient-add").addEventListener("click", async () => {
    const name = el("backup-recipient-name").value.trim();
    const pem = el("backup-recipient-key").value.trim();
    if (!name || !pem) {
      el("backup-recipients-status").textContent = "Enter a name and a public key.";
      return;
    }
    try {
      const r = await api("/api/v1/backup/recipients", { method: "POST", body: JSON.stringify({ name, public_key_pem: pem }) });
      el("backup-recipient-name").value = "";
      el("backup-recipient-key").value = "";
      el("backup-recipients-status").textContent = `Recipient added (${(r.fingerprint_sha256 || "").slice(0, 16)}…).`;
      await loadBackupRecipients();
    } catch (err) {
      el("backup-recipients-status").textContent = `Add failed: ${err.message}`;
    }
  });
  el("backup-now-btn").addEventListener("click", async () => {
    el("backup-output").textContent = "Running backup...";
    try {
      const res = await api("/api/v1/backup/run", { method: "POST" });
      let msg = res.skipped ? "No changes since the last backup — skipped." : `Backup created: ${res.created}`;
      if (res.remote) msg += ` · pushed to ${res.remote}`;
      if (res.remote_error) msg += ` · remote push FAILED: ${res.remote_error}`;
      el("backup-output").textContent = msg;
      await loadBackupList();
    } catch (err) {
      el("backup-output").textContent = err.message;
    }
  });
  el("backup-export-link").addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      await downloadApi("/api/v1/backup/export", "akamana-backup.sql");
    } catch (err) {
      el("backup-output").textContent = err.message;
    }
  });
  el("backup-import-file").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    importBackupFile(file);
    e.target.value = "";
  });

  el("user-create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/users", { method: "POST", body: JSON.stringify(data) });
      e.target.reset();
      await loadUsersTable();
      el("users-output").textContent = "User created";
    } catch (err) {
      el("users-output").textContent = err.message;
    }
  });
  el("users-refresh").addEventListener("click", async () => {
    await loadUsersTable();
  });

  el("token-create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const scopes = Array.from(document.querySelectorAll(".token-scope-cb"))
      .filter((cb) => cb.checked)
      .map((cb) => cb.value);
    if (!scopes.length) {
      el("tokens-output").textContent = "Select at least one scope.";
      return;
    }
    const name = el("token-name").value.trim();
    const comment = el("token-comment").value.trim();
    const expiryRaw = el("token-expiry").value.trim();
    const payload = { name, scopes };
    if (comment) payload.comment = comment;
    if (expiryRaw) payload.expires_in_days = Number(expiryRaw);
    try {
      const res = await api("/api/v1/tokens", { method: "POST", body: JSON.stringify(payload) });
      el("token-reveal-value").textContent = res.token;
      el("token-reveal").hidden = false;
      e.target.reset();
      document.querySelectorAll(".token-scope-cb").forEach((cb) => (cb.checked = false));
      await loadTokensTable();
      el("tokens-output").textContent = "Token created — copy it now.";
    } catch (err) {
      el("tokens-output").textContent = `Create failed: ${err.message}`;
    }
  });
  el("token-copy").addEventListener("click", async () => {
    const val = el("token-reveal-value").textContent;
    const ok = await copyTextToClipboard(val);
    flashCopyFeedback(el("token-copy"), ok);
    el("tokens-output").textContent = ok
      ? "Token copied to clipboard."
      : "Copy failed — select and copy manually.";
  });
  el("tokens-refresh").addEventListener("click", async () => {
    await loadTokensTable();
  });

  el("ssh-cert-source").addEventListener("change", syncSshCertSourceRows);
  el("ssh-cert-type").addEventListener("change", syncSshCertTypeHint);
  el("ssh-certs-refresh").addEventListener("click", async () => {
    await loadSshCertsTable().catch((err) => (el("ssh-certs-output").textContent = err.message));
  });
  // ---- Import d'une cle SSH : lecture locale du fichier, puis analyse serveur.
  function wireKeyFileInput(fileId, textareaId) {
    const input = el(fileId);
    if (!input) return;
    input.addEventListener("change", () => {
      const file = input.files && input.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        el(textareaId).value = String(reader.result || "").trim();
        el("ssh-import-analysis").textContent =
          `Loaded ${file.name}. Analyse it to see what it is.`;
      };
      reader.onerror = () => {
        el("ssh-import-analysis").textContent = `Could not read ${file.name}.`;
      };
      // The file never leaves the browser at this point; only the analyse
      // button sends anything, and only to this server.
      reader.readAsText(file);
    });
  }
  wireKeyFileInput("ssh-import-public-file", "ssh-import-public");
  wireKeyFileInput("ssh-import-private-file", "ssh-import-private");

  function renderKeyAnalysis(a) {
    const box = el("ssh-import-analysis");
    box.innerHTML = "";

    const verdict = document.createElement("p");
    const blocking = Array.isArray(a.errors) && a.errors.length > 0;
    verdict.className = `diagnostic-banner diag-${blocking ? "bad" : "ok"}`;
    verdict.textContent = blocking
      ? "This key should not be imported as is."
      : "This key looks usable.";
    box.appendChild(verdict);

    const facts = [
      ["Supplied", a.supplied === "pair" ? "public and private key" : `${a.supplied} key only`],
      ["Algorithm", a.algorithm],
      ["Size", a.bits ? `${a.bits} bits` : "unknown"],
      ["Fingerprint", a.fingerprint_sha256],
      ["Comment", a.comment || "(none)"],
    ];
    if (a.matches_public !== null && a.matches_public !== undefined) {
      facts.push([
        "Halves match",
        a.matches_public ? "yes" : "no — these are two different keys",
      ]);
    }
    if (a.encrypted) facts.push(["Passphrase", "yes, the private key is encrypted"]);

    const dl = document.createElement("dl");
    dl.className = "kv-list";
    facts.forEach(([k, v]) => {
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v;
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    box.appendChild(dl);

    [["errors", "Problems"], ["warnings", "Worth knowing"]].forEach(([key, title]) => {
      const items = Array.isArray(a[key]) ? a[key] : [];
      if (!items.length) return;
      const h = document.createElement("h4");
      h.textContent = title;
      box.appendChild(h);
      const ul = document.createElement("ul");
      ul.className = key === "errors" ? "san-list diag-bad" : "san-list";
      items.forEach((t) => {
        const li = document.createElement("li");
        li.textContent = t;
        ul.appendChild(li);
      });
      box.appendChild(ul);
    });
  }

  el("ssh-import-analyze").addEventListener("click", async () => {
    const publicKey = el("ssh-import-public").value.trim();
    const privateKey = el("ssh-import-private").value.trim();
    const box = el("ssh-import-analysis");
    if (!publicKey && !privateKey) {
      box.textContent = "Paste a public key, a private key, or both.";
      return;
    }
    box.textContent = "Analysing...";
    try {
      const a = await api("/api/v1/ssh/keys/analyze", {
        method: "POST",
        body: JSON.stringify({
          public_key: publicKey || null,
          private_key: privateKey || null,
        }),
      });
      renderKeyAnalysis(a);
    } catch (err) {
      box.textContent = err.message;
    }
  });

  el("ssh-import-clear").addEventListener("click", () => {
    ["ssh-import-public", "ssh-import-private"].forEach((id) => (el(id).value = ""));
    ["ssh-import-public-file", "ssh-import-private-file"].forEach((id) => (el(id).value = ""));
    el("ssh-import-analysis").textContent = "Paste a key or load a file, then analyse it.";
  });

  el("ssh-cert-copy-cert").addEventListener("click", async () => {
    const ok = await copyTextToClipboard(el("ssh-cert-result-cert").textContent);
    flashCopyFeedback(el("ssh-cert-copy-cert"), ok);
    el("ssh-certs-output").textContent = ok
      ? "Certificate copied."
      : "Copy failed - select the certificate and copy it manually.";
  });
  el("ssh-cert-copy-private").addEventListener("click", async () => {
    const ok = await copyTextToClipboard(el("ssh-cert-result-private").textContent);
    flashCopyFeedback(el("ssh-cert-copy-private"), ok);
    el("ssh-certs-output").textContent = ok
      ? "Private key copied."
      : "Copy failed - select the key and copy it manually.";
  });
  el("ssh-cert-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const principals = el("ssh-cert-principals").value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!principals.length) {
      el("ssh-certs-output").textContent = "Enter at least one principal.";
      return;
    }
    const payload = {
      cert_type: el("ssh-cert-type").value,
      key_id: el("ssh-cert-keyid").value.trim(),
      principals,
      valid_days: Number(el("ssh-cert-validity").value) || 30,
    };
    const src = el("ssh-cert-source").value;
    if (src === "generate") {
      payload.generate = { comment: el("ssh-cert-gen-comment").value.trim() || payload.key_id, valid_days: payload.valid_days, publish_private_key: true };
    } else if (src === "existing") {
      payload.ssh_key_id = el("ssh-cert-existing").value;
    } else {
      payload.public_key = el("ssh-cert-paste").value.trim();
    }
    try {
      const res = await api("/api/v1/ssh/certificates", { method: "POST", body: JSON.stringify(payload) });
      el("ssh-cert-result-cert").textContent = res.certificate;
      el("ssh-cert-result").hidden = false;
      const hasPriv = Boolean(res.private_key);
      el("ssh-cert-result-private-wrap").hidden = !hasPriv;
      if (hasPriv) el("ssh-cert-result-private").textContent = res.private_key;
      await loadSshCertsTable();
      el("ssh-certs-output").textContent = "Certificate signed.";
    } catch (err) {
      el("ssh-certs-output").textContent = `Sign failed: ${err.message}`;
    }
  });

  el("app-add-btn").addEventListener("click", () => openAppModal(null));
  el("app-cancel").addEventListener("click", () => el("app-modal").close());
  el("app-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await saveApplication();
    } catch (err) {
      el("app-error").textContent = err.message;
    }
  });

  el("cred-add-btn").addEventListener("click", () => openCredModal(null));
  el("cred-cancel").addEventListener("click", () => el("cred-modal").close());
  el("cred-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await saveCredential();
    } catch (err) {
      el("cred-error").textContent = err.message;
    }
  });

  el("scan-network-btn").addEventListener("click", scanNetwork);
  el("scan-add-selected").addEventListener("click", addSelectedScanned);
  el("host-add-btn").addEventListener("click", () => openHostModal(null));
  el("host-modal-cancel").addEventListener("click", () => el("host-modal").close());
  el("host-detail-close").addEventListener("click", () => {
    el("host-detail-panel").hidden = true;
  });
  el("host-modal-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    const hid = el("host-modal-id").value;
    try {
      await api(hid ? `/api/v1/machines/${hid}` : "/api/v1/machines", {
        method: hid ? "PATCH" : "POST",
        body: JSON.stringify({
          hostname: d.hostname,
          ip_address: d.ip_address,
          owner: d.owner,
          environment: d.environment,
          os_type: d.os_type || null,
        }),
      });
      el("host-modal").close();
      if (state.currentPage === "machines") {
        await loadMachinesPage();
      } else {
        await loadHostsPage();
      }
    } catch (err) {
      el("host-modal-error").textContent = err.message;
    }
  });
  el("host-settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.selectedHostId) return;
    try {
      const monitorOnly = el("host-monitor-only").checked;
      await api(`/api/v1/machines/${state.selectedHostId}`, {
        method: "PATCH",
        body: JSON.stringify({
          hostname: el("host-name").value,
          ip_address: el("host-ip").value,
          os_type: el("host-os").value || null,
          alert_email: el("host-alert-email").value || null,
          test_url: el("host-test-url").value || null,
          monitor_only: monitorOnly,
        }),
      });
      const m = state.machines.find((x) => x.id === state.selectedHostId);
      if (m) {
        m.hostname = el("host-name").value;
        m.ip_address = el("host-ip").value;
        m.os_type = el("host-os").value || null;
        m.alert_email = el("host-alert-email").value || null;
        m.test_url = el("host-test-url").value || null;
        m.monitor_only = monitorOnly;
      }
      el("host-detail-title").textContent = `Manage ${el("host-name").value}`;
      renderHostsTable();
      el("hosts-output").textContent = "Host settings saved.";
    } catch (err) {
      el("hosts-output").textContent = err.message;
    }
  });
  el("host-cred-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.selectedHostId) return;
    const d = Object.fromEntries(new FormData(e.target).entries());
    if (!d.credential_id) {
      el("hosts-output").textContent = "Select a credential first.";
      return;
    }
    try {
      await api("/api/v1/host-credentials", {
        method: "POST",
        body: JSON.stringify({
          machine_id: state.selectedHostId,
          credential_id: d.credential_id,
          protocol: d.protocol,
          port: d.port ? Number(d.port) : null,
          is_default: d.hc_is_default === "yes",
        }),
      });
      e.target.reset();
      await loadHostDetails();
    } catch (err) {
      el("hosts-output").textContent = err.message;
    }
  });
  el("certbot-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.selectedHostId) return;
    const d = Object.fromEntries(new FormData(e.target).entries());
    try {
      await api("/api/v1/certbot/configs", {
        method: "POST",
        body: JSON.stringify({
          machine_id: state.selectedHostId,
          domains: d.domains,
          email: d.email || null,
          challenge: d.challenge,
          webroot_path: d.webroot_path || null,
          dns_plugin: d.dns_plugin || null,
          extra_args: d.extra_args || null,
          staging: d.cb_staging === "yes",
          auto_renew: d.cb_auto_renew === "yes",
          renew_days_before: d.renew_days_before ? Number(d.renew_days_before) : 30,
        }),
      });
      e.target.reset();
      await loadCertbotConfigs(state.selectedHostId);
      el("hosts-output").textContent = "Certbot config added.";
    } catch (err) {
      el("hosts-output").textContent = err.message;
    }
  });
  el("host-app-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!state.selectedHostId) return;
    const d = Object.fromEntries(new FormData(e.target).entries());
    if (!d.application_id) {
      el("hosts-output").textContent = "Select an application first.";
      return;
    }
    try {
      await api("/api/v1/host-applications", {
        method: "POST",
        body: JSON.stringify({
          machine_id: state.selectedHostId,
          application_id: d.application_id,
          tls_key_id: d.tls_key_id || null,
          cert_path: d.cert_path || null,
          key_path: d.key_path || null,
          chain_path: d.chain_path || null,
          reload_command: d.reload_command || null,
          credential_id: d.credential_id || null,
          auto_deploy: d.ha_auto_deploy === "yes",
        }),
      });
      e.target.reset();
      await loadHostDetails();
    } catch (err) {
      el("hosts-output").textContent = err.message;
    }
  });

  el("mon-host-select").addEventListener("change", (e) => {
    state.monHostId = e.target.value;
    renderMonEditor();
  });
  el("mon-add-host").addEventListener("click", () => openHostModal(null));
  el("mon-save-host").addEventListener("click", async () => {
    if (!state.monHostId) return;
    try {
      await api(`/api/v1/machines/${state.monHostId}`, {
        method: "PATCH",
        body: JSON.stringify({
          hostname: el("mon-name").value,
          ip_address: el("mon-ip").value,
          owner: el("mon-owner").value,
          environment: el("mon-env").value,
          os_type: el("mon-os").value || null,
        }),
      });
      await loadMachinesPage();
      el("mon-host-select").value = state.monHostId;
      renderMonEditor();
      el("mon-editor-status").textContent = "Host saved.";
    } catch (err) {
      el("mon-editor-status").textContent = err.message;
    }
  });
  el("mon-delete-host").addEventListener("click", async () => {
    if (!state.monHostId) return;
    const m = state.machines.find((x) => x.id === state.monHostId);
    if (!confirm(`Delete host ${m ? m.hostname : ""}?`)) return;
    try {
      await api(`/api/v1/machines/${state.monHostId}`, { method: "DELETE" });
      state.monHostId = "";
      await loadMachinesPage();
      el("mon-editor-status").textContent = "Host deleted.";
    } catch (err) {
      el("mon-editor-status").textContent = err.message;
    }
  });
  el("mon-add-port").addEventListener("click", async () => {
    if (!state.monHostId) return;
    const port = Number(el("mon-new-port").value);
    if (!port) return;
    try {
      await api("/api/v1/machines/monitor/ports", {
        method: "POST",
        body: JSON.stringify({ machine_id: state.monHostId, port, sni_host: "" }),
      });
      el("mon-new-port").value = "";
      await refreshMonAfterChange();
    } catch (err) {
      el("mon-editor-status").textContent = err.message;
    }
  });
  el("mon-add-domain").addEventListener("click", async () => {
    const domain = el("mon-domain").value.trim();
    const status = el("mon-domain-status");
    if (!domain) {
      status.textContent = "Enter a domain name first.";
      return;
    }
    const body = { domain };
    const rawPort = el("mon-domain-port").value.trim();
    if (rawPort) body.port = Number(rawPort);

    status.textContent = `Resolving ${domain}...`;
    try {
      const r = await api("/api/v1/machines/monitor/domains", {
        method: "POST",
        body: JSON.stringify(body),
      });
      // Spell out what was decided on the operator's behalf: which host the
      // name landed on, and what actually answered.
      const parts = [`${r.domain} \u2192 ${r.ip_address}`];
      parts.push(
        r.machine_created
          ? "new host registered"
          : `attached to host ${r.machine_hostname}`,
      );
      parts.push(`monitoring port ${r.port}`);
      parts.push(
        `HTTPS ${r.responds_https ? "yes" : "no"}, HTTP ${r.responds_http ? "yes" : "no"}`,
      );
      if (!r.monitor_port_created) parts.push("already monitored");
      status.textContent = parts.join(" \u00b7 ");
      el("mon-domain").value = "";
      el("mon-domain-port").value = "";
      await loadMachinesPage();
      await refreshMonAfterChange();
    } catch (err) {
      status.textContent = err.message;
    }
  });

  el("mon-scan-all").addEventListener("click", async () => {
    el("mon-editor-status").textContent = "Scanning all enabled ports...";
    await api("/api/v1/machines/monitor/scan", { method: "POST" });
    await refreshMonAfterChange();
    el("mon-editor-status").textContent = "Scan completed.";
  });

  el("import-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    try {
      let machine_id = null;
      if (data.assign_machine === "yes") {
        if (!data.hostname || !data.ip_address) {
          throw new Error("Machine name and IP address are required when assigning a machine.");
        }
        machine_id = await findOrCreateMachine(data);
      }
      await api("/api/v1/certificates/tls/import", {
        method: "POST",
        body: JSON.stringify({
          machine_id,
          root_id: Number(data.root_id),
          cert_level: data.cert_level,
          parent_cert_id: null,
          cert_pem: data.cert_pem,
          private_key_pem: data.private_key_pem || "",
          publish_private_key: data.publish_private_key === "yes",
          cipher: data.cipher,
          key_length: Number(data.key_length),
        }),
      });
      el("import-error").textContent = "";
      el("import-modal").close();
      await refreshAll();
    } catch (err) {
      el("import-error").textContent = err.message;
    }
  });

  el("logs-filter-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target).entries());
    await loadLogs(f);
  });
  document.querySelectorAll("[data-log-tab]").forEach((b) => {
    b.addEventListener("click", () => {
      setLogsTab(b.dataset.logTab);
    });
  });

  el("password-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    const out = await api("/api/v1/users/me/password", { method: "POST", body: JSON.stringify(d) });
    renderObjectAsTable(el("profile-output"), out);
  });

  el("deploy-target").addEventListener("change", () => {
    state.deployGuide = null;
    seedDeployDefaults(true);
    renderDeploymentAssistant();
  });
  el("deploy-build").addEventListener("click", buildDeploymentGuide);
}

function setPublishDefaultByLevel() {
  // Leaf certificates need their private key to deploy, so default to exportable.
  const isLeaf = el("cf-cert-level").value !== "intermediate";
  const val = isLeaf ? "yes" : "no";
  const radio = document.querySelector(`#cert-form input[name='publish_private_key'][value='${val}']`);
  if (radio) radio.checked = true;
}

function toggleMachineAssignmentUi() {
  const isIntermediate = el("cf-cert-level").value === "intermediate";
  const assignYes = document.querySelector("#cf-assign-machine-wrap input[name='assign_machine'][value='yes']");
  const assignNo = document.querySelector("#cf-assign-machine-wrap input[name='assign_machine'][value='no']");
  if (isIntermediate) {
    assignNo.checked = true;
    assignYes.disabled = true;
  } else {
    assignYes.disabled = false;
  }
  const assignEnabled = !isIntermediate && assignYes.checked;
  const machineSection = el("cf-machine-ssh-section");
  if (machineSection) machineSection.hidden = !assignEnabled;
  // Only the machine-specific fields depend on assignment; SSH key fields are always usable.
  ["cf-hostname", "cf-ip", "cf-owner", "cf-env"].forEach((id) => {
    el(id).disabled = !assignEnabled;
  });
}

function toggleImportMachineAssignmentUi() {
  const assignYes = document.querySelector("#im-assign-machine-wrap input[name='assign_machine'][value='yes']");
  const assignEnabled = assignYes.checked;
  ["im-hostname", "im-ip", "im-owner", "im-env"].forEach((id) => {
    el(id).disabled = !assignEnabled;
  });
}

async function fillParentIntermediateOptions() {
  const rootId = Number(el("cf-root-id").value || state.selectedRootId);
  const level = el("cf-cert-level").value;
  const parent = el("cf-parent-id");
  parent.innerHTML = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "(none)";
  parent.appendChild(none);
  if (level !== "leaf") return;
  const intermediates = state.tls.filter((t) => Number(t.root_ca_id || 1) === rootId && t.cert_level === "intermediate" && !t.is_revoked);
  intermediates.forEach((t) => {
    const o = document.createElement("option");
    o.value = t.id;
    o.textContent = t.common_name;
    parent.appendChild(o);
  });
  // Default to signing with an intermediate when one exists (best practice).
  if (intermediates.length) parent.value = intermediates[0].id;
}

/**
 * A password-reset mail lands on `/#reset=<token>`. Pull the token out and drop
 * the fragment so it doesn't linger in the address bar or in a shared link.
 * Returns the token rather than storing it: the caller may need to log out
 * first, and `logout()` resets `state.auth`.
 */
function takeResetTokenFromUrl() {
  const match = /[#&]reset=([A-Za-z0-9_-]+)/.exec(window.location.hash || "");
  if (!match) return null;
  history.replaceState(null, "", window.location.pathname + window.location.search);
  return match[1];
}

async function init() {
  bindEvents();
  applyMode();
  setLogsTab(state.logsTab);
  await loadBranding();
  await loadRoots().catch(() => {});
  toggleMachineAssignmentUi();
  toggleImportMachineAssignmentUi();
  authUi();
  if (state.token) {
    try {
      await refreshAll();
      await loadDefaults().catch(() => {});
    } catch (_) {
      logout();
    }
  }
  const resetToken = takeResetTokenFromUrl();
  if (resetToken) {
    // Order matters: `logout()` clears `state.auth`, so stash the token after it.
    if (state.token) logout();
    state.auth.resetToken = resetToken;
    openLogin("reset");
    updatePasswordMeter();
  }
}

init();
