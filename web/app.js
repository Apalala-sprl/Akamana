const state = {
  token: sessionStorage.getItem("ezkey_token") || "",
  user: null,
  lang: "en",
  tab: "tls",
  logsTab: "actions",
  currentPage: "certs",
  selected: null,
  selectedRootId: 1,
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
  linux: {
    title: "Linux",
    desc: "Add the CA to system trust store.",
    steps: [
      "Download the root certificate file (.pem).",
      "Copy it to /usr/local/share/ca-certificates/.",
      "Run update-ca-certificates (Debian/Ubuntu).",
      "Restart services using TLS if needed.",
    ],
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
  id: "Unique identifier of this record in EZKey.",
  common_name: "Main name that this certificate identifies (for example a DNS name).",
  cert_level: "Certificate role in the chain: root, intermediate, or leaf/service certificate.",
  organization: "Organization that owns and manages this certificate authority.",
  serial_hex: "Certificate serial number used for audits and revocation checks.",
  cipher: "Cryptographic algorithm used to generate keys and sign the certificate.",
  key_length: "Size of the key. Larger keys can be stronger but may cost more CPU.",
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
  publish_private_key: "If enabled, private key export can be downloaded from EZKey.",
  allow_private_key_export: "Whether EZKey allows downloading the private key.",
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
    const v = document.createElement("div");
    v.className = "value-text";
    v.textContent = formatValue(value[key]);
    td.appendChild(v);
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
    throw new Error(typeof body === "object" ? pretty(body) : String(body));
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

function renderDeploy(privateMode) {
  const emptyNode = el(privateMode ? "private-root-meta" : "public-empty-msg");
  const content = el(privateMode ? "page-deploy" : "public-deploy-content");
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
    b.textContent = OS_INFO[platform].title;
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
  dl.href = `/api/v1/certificates/root/download/${state.deployPlatform}?root_id=${encodeURIComponent(state.selectedRootId)}`;
}

async function login(username, password) {
  const out = await api("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  state.token = out.access_token;
  state.user = { username: out.username, role: out.role };
  sessionStorage.setItem("ezkey_token", out.access_token);
  authUi();
  await refreshAll();
}

function logout() {
  state.token = "";
  state.user = null;
  state.selected = null;
  sessionStorage.removeItem("ezkey_token");
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
    return "Compatibility: Ed25519 is modern and fast, but some legacy TLS clients/appliances may fail. Use RSA for widest browser compatibility.";
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
    formGrid.insertAdjacentElement("afterend", hint);
  }
  hint.textContent = cipherCompatibilityMessage(select.value, domain);
}

function refreshCipherCompatibilityHints() {
  CIPHER_COMPATIBILITY_CONFIG.forEach(upsertCipherCompatibilityHint);
}

function renderList() {
  const list = el("cert-list");
  list.innerHTML = "";
  const rootId = Number(state.selectedRootId);
  let src = [];
  if (state.tab === "tls") {
    const tlsForRoot = state.tls.filter((t) => Number(t.root_ca_id || 1) === rootId);
    const root = selectedRoot();
    if (root) {
      src.push({
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
      });
    }
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
    intermediates.forEach((intermediate) => {
      src.push(intermediate);
      const children = leavesByParent.get(intermediate.id) || [];
      children.forEach((leaf) => src.push(leaf));
      leavesByParent.delete(intermediate.id);
    });
    const rootLeaves = leavesByParent.get("__root__") || [];
    rootLeaves.forEach((leaf) => src.push(leaf));
    leavesByParent.delete("__root__");
    Array.from(leavesByParent.values()).flat().forEach((leaf) => src.push(leaf));
  } else {
    src = [...state.ssh];
  }
  src.forEach((item) => {
    const li = document.createElement("li");
    if (state.tab === "tls") {
      const d = item.cert_level === "root" ? 0 : (item.cert_level === "intermediate" ? 1 : 2);
      li.classList.add(`depth-${d}`);
    }
    if (state.selected && state.selected.id === item.id) li.classList.add("active");
    const left = document.createElement("div");
    left.textContent = state.tab === "tls"
      ? `${item.common_name} (${item.cert_level || "leaf"})`
      : `${item.ssh_username || "user"}@${item.machine_name || "machine"}`;
    const right = document.createElement("small");
    right.textContent = item.is_revoked ? "revoked" : "active";
    li.append(left, right);
    li.addEventListener("click", () => selectCertificate(item));
    list.appendChild(li);
  });
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

function deployArtifact(title, bodyText, copyLabel = "Copy") {
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
    el("cert-action-status").textContent = ok ? `${title} copied to clipboard.` : `Unable to copy ${title}.`;
  });
  head.append(h, copyBtn);
  const pre = document.createElement("pre");
  pre.textContent = bodyText;
  wrap.append(head, pre);
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
  if (!cert || cert.is_root_row || state.tab !== "tls") {
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
  artifacts.appendChild(deployArtifact("Private key (PEM)", guide.artifacts?.private_key_pem || "Unavailable", "Copy key"));
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

async function loadDefaults() {
  const data = await api("/api/v1/settings/defaults");
  el("default_tls_cipher").value = data.default_tls_cipher;
  el("default_tls_key_length").value = String(data.default_tls_key_length);
  el("default_ssh_cipher").value = data.default_ssh_cipher;
  el("default_ssh_key_length").value = String(data.default_ssh_key_length);
  refreshCipherCompatibilityHints();
  el("cert_owners_json").value = data.cert_owners_json || '["lab-ops","security","devops"]';
  let owners = ["lab-ops", "security", "devops"];
  try {
    const parsed = JSON.parse(el("cert_owners_json").value);
    if (Array.isArray(parsed) && parsed.length) owners = parsed.map((x) => String(x));
  } catch (_) {}
  const ownerOptions = owners.map((o) => `<option value="${o}">${o}</option>`).join("");
  ["cf-owner", "im-owner"].forEach((id) => {
    const node = el(id);
    if (node) node.innerHTML = ownerOptions;
  });
}

function fillMachineSelectOptions() {
  const sel = el("monitor-machine-id");
  if (!sel) return;
  sel.innerHTML = "";
  state.machines.forEach((m) => {
    const o = document.createElement("option");
    o.value = m.id;
    o.textContent = `${m.hostname} (${m.ip_address})`;
    sel.appendChild(o);
  });
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
  if (!item) {
    el("machine-cert-detail").textContent = "Select a monitored port row to view full certificate and chain details.";
    return;
  }
  renderObjectAsTable(el("machine-cert-detail"), {
    monitor_port_id: item.id,
    machine_id: item.machine_id,
    hostname: item.hostname,
    ip_address: item.ip_address,
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
    cert_serial_hex: item.cert_serial_hex,
    certificate_chain: item.cert_chain,
    diagnostic: item.diagnostic,
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
      String(item.port),
      statusText,
      expiresText,
      checkedText,
      item.diagnostic || "—",
    ];
    values.forEach((v) => {
      const td = document.createElement("td");
      td.textContent = String(v || "—");
      tr.appendChild(td);
    });

    const actionTd = document.createElement("td");
    const scanBtn = document.createElement("button");
    scanBtn.type = "button";
    scanBtn.textContent = "Scan";
    scanBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await api(`/api/v1/machines/monitor/ports/${item.id}/scan`, { method: "POST" });
      await loadMachineMonitorRows();
      el("machines-output").textContent = `Scanned ${item.hostname}:${item.port}`;
    });
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.textContent = item.monitor_enabled ? "Disable" : "Enable";
    toggleBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await api(`/api/v1/machines/monitor/ports/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ monitor_enabled: !item.monitor_enabled }),
      });
      await loadMachineMonitorRows();
      el("machines-output").textContent = `${item.hostname}:${item.port} monitoring ${item.monitor_enabled ? "disabled" : "enabled"}.`;
    });
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.textContent = "Edit port";
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
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm(`Delete monitor ${item.hostname}:${item.port}?`)) return;
      await api(`/api/v1/machines/monitor/ports/${item.id}`, { method: "DELETE" });
      if (state.selectedMachineMonitorRow?.id === item.id) {
        state.selectedMachineMonitorRow = null;
      }
      await loadMachineMonitorRows();
    });
    actionTd.append(scanBtn, toggleBtn, editBtn, delBtn);
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
  fillMachineSelectOptions();
  await loadMachineMonitorRows();
}

async function downloadApi(path, fallbackName) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { headers });
  if (!res.ok) throw new Error(`Download failed (${res.status})`);
  const blob = await res.blob();
  const dispo = res.headers.get("content-disposition") || "";
  const filename = (dispo.match(/filename=\"([^\"]+)\"/) || [])[1] || fallbackName;
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

async function loadUsersTable() {
  const rows = await api("/api/v1/users");
  const tbody = el("users-tbody");
  tbody.innerHTML = "";
  rows.forEach((u) => {
    const tr = document.createElement("tr");
    const tdUser = document.createElement("td");
    tdUser.textContent = u.username;
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

    const saveRole = document.createElement("button");
    saveRole.type = "button";
    saveRole.textContent = "Save role";
    saveRole.addEventListener("click", async () => {
      await api(`/api/v1/users/${u.id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role: roleSelect.value }),
      });
      el("users-output").textContent = "Role updated";
    });

    const resetPwd = document.createElement("button");
    resetPwd.type = "button";
    resetPwd.textContent = "Reset password";
    resetPwd.addEventListener("click", async () => {
      const p = prompt(`New password for ${u.username} (min 12 chars):`);
      if (!p) return;
      await api(`/api/v1/users/${u.id}/password`, {
        method: "POST",
        body: JSON.stringify({ new_password: p }),
      });
      el("users-output").textContent = "Password reset";
    });

    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete user ${u.username}?`)) return;
      await api(`/api/v1/users/${u.id}`, { method: "DELETE" });
      await loadUsersTable();
    });

    actions.append(saveRole, resetPwd, del);
    tdActions.appendChild(actions);
    tr.append(tdUser, tdRole, tdCreated, tdActions);
    tbody.appendChild(tr);
  });
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

function bindEvents() {
  el("menu-toggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const panel = el("main-menu");
    setMainMenuOpen(panel.hidden);
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

  document.querySelectorAll(".nav-item").forEach((b) => {
    b.addEventListener("click", async () => {
      showPage(b.dataset.page);
      if (b.dataset.page === "logs") await loadLogs();
      if (b.dataset.page === "users") {
        await loadUsersTable();
      }
      if (b.dataset.page === "machines") {
        await loadMachinesPage();
      }
      if (b.dataset.page === "deploy") renderDeploy(true);
      if (b.dataset.page === "settings") {
        await loadDefaults();
        await loadMachineMonitorSettings().catch(() => {});
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

  el("login-open").addEventListener("click", () => el("login-modal").showModal());
  el("login-cancel").addEventListener("click", () => el("login-modal").close());
  el("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    try {
      await login(data.username, data.password);
      el("login-error").textContent = "";
      el("login-modal").close();
    } catch (err) {
      el("login-error").textContent = err.message;
    }
  });
  el("logout-btn").addEventListener("click", logout);

  document.querySelectorAll("[data-tab]").forEach((b) => {
    b.addEventListener("click", () => {
      state.tab = b.dataset.tab;
      document.querySelectorAll("[data-tab]").forEach((x) => x.classList.toggle("active", x.dataset.tab === state.tab));
      const tls = state.tab === "tls";
      document.querySelectorAll(".tls-only").forEach((n) => (n.hidden = !tls));
      document.querySelectorAll(".ssh-only").forEach((n) => (n.hidden = tls));
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

  el("add-cert").addEventListener("click", async () => {
    el("cf-root-id").value = String(state.selectedRootId);
    document.querySelector("#cf-assign-machine-wrap input[name='assign_machine'][value='no']").checked = true;
    toggleMachineAssignmentUi();
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
        cert_owners_json: d.cert_owners_json || '["lab-ops","security","devops"]',
      }),
    });
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

  el("user-create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target).entries());
    await api("/api/v1/users", { method: "POST", body: JSON.stringify(data) });
    await loadUsersTable();
    el("users-output").textContent = "User created";
  });
  el("users-refresh").addEventListener("click", async () => {
    await loadUsersTable();
  });

  el("machine-create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    await api("/api/v1/machines", {
      method: "POST",
      body: JSON.stringify({
        hostname: d.hostname,
        ip_address: d.ip_address,
        owner: d.owner,
        environment: d.environment,
      }),
    });
    e.target.reset();
    el("mm-owner").value = "lab-ops";
    el("mm-env").value = "internal-lab";
    await loadMachinesPage();
    el("machines-output").textContent = "Machine added.";
  });

  el("monitor-port-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target).entries());
    await api("/api/v1/machines/monitor/ports", {
      method: "POST",
      body: JSON.stringify({
        machine_id: d.machine_id,
        port: Number(d.port),
        monitor_enabled: true,
      }),
    });
    await loadMachineMonitorRows();
    el("machines-output").textContent = "Monitored port added.";
  });

  el("monitor-add-default-ports").addEventListener("click", async () => {
    const machineId = el("monitor-machine-id").value;
    const raw = (state.machineMonitorSettings?.default_ports_csv || el("mm-default-ports").value || "443,8443");
    const ports = Array.from(
      new Set(
        String(raw)
          .split(",")
          .map((p) => Number(String(p).trim()))
          .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535),
      ),
    );
    if (!machineId || !ports.length) return;
    for (const port of ports) {
      try {
        await api("/api/v1/machines/monitor/ports", {
          method: "POST",
          body: JSON.stringify({ machine_id: machineId, port, monitor_enabled: true }),
        });
      } catch (_) {}
    }
    await loadMachineMonitorRows();
    el("machines-output").textContent = `Default ports added: ${ports.join(", ")}`;
  });

  el("monitor-scan-all").addEventListener("click", async () => {
    await api("/api/v1/machines/monitor/scan", { method: "POST" });
    await loadMachineMonitorRows();
    el("machines-output").textContent = "Scan completed for all enabled monitored ports.";
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
  ["cf-hostname", "cf-ip", "cf-owner", "cf-env", "cf-ssh-user", "cf-ssh-cipher", "cf-ssh-key-length"].forEach((id) => {
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
}

async function init() {
  bindEvents();
  setLogsTab(state.logsTab);
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
}

init();
