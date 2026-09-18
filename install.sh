#!/usr/bin/env bash
# Akamana — installation en une commande (Linux / macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/Apalala-sprl/Akamana/main/install.sh | bash
#
# Ce que fait ce script, dans l'ordre :
#   1. vérifie que Docker et Docker Compose sont là (propose de les installer
#      sur Debian/Ubuntu) ;
#   2. télécharge le dépôt dans le répertoire choisi — pas besoin de git ;
#   3. pose les quelques questions utiles (répertoire, port, compte admin) ;
#   4. génère des secrets forts : clé de chiffrement des clés privées, secret
#      JWT, mots de passe MariaDB, mot de passe admin si vous n'en donnez pas ;
#   5. écrit la configuration — jamais affichée, jamais dans l'historique du
#      shell — et lance les conteneurs ;
#   6. attend que l'application réponde, puis vous dit où la trouver.
#
# Relancer le script sur une installation existante ne régénère rien : il
# garde la configuration en place et se contente de mettre à jour et relancer.
#
# Tout se pilote aussi sans question, par variables d'environnement :
#   AKAMANA_DIR, AKAMANA_HTTP_PORT, AKAMANA_ADMIN_USER, AKAMANA_ADMIN_PASSWORD,
#   AKAMANA_PUBLIC_URL, AKAMANA_NONINTERACTIVE=1

set -euo pipefail

DEPOT="${AKAMANA_REPO:-Apalala-sprl/Akamana}"
BRANCHE="${AKAMANA_BRANCH:-main}"
ARCHIVE="https://github.com/${DEPOT}/archive/refs/heads/${BRANCHE}.tar.gz"

# ── Affichage ────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  GRAS=$'\e[1m'; VERT=$'\e[32m'; JAUNE=$'\e[33m'; ROUGE=$'\e[31m'; FIN=$'\e[0m'
else
  GRAS=""; VERT=""; JAUNE=""; ROUGE=""; FIN=""
fi
titre()  { printf '\n%s%s%s\n' "$GRAS" "$1" "$FIN"; }
ok()     { printf '  %s✓%s %s\n' "$VERT" "$FIN" "$1"; }
info()   { printf '  · %s\n' "$1"; }
avert()  { printf '  %s!%s %s\n' "$JAUNE" "$FIN" "$1"; }
erreur() { printf '  %s✗ %s%s\n' "$ROUGE" "$1" "$FIN" >&2; exit 1; }

# Lu depuis le terminal même quand le script arrive par `curl | bash` — dans
# ce cas stdin est le script lui-même, pas le clavier.
demander() {
  local question="$1" defaut="$2" reponse=""
  if [ "${AKAMANA_NONINTERACTIVE:-0}" = "1" ] || [ ! -r /dev/tty ]; then
    printf '%s' "$defaut"; return
  fi
  printf '  %s [%s] : ' "$question" "$defaut" > /dev/tty
  IFS= read -r reponse < /dev/tty || true
  printf '%s' "${reponse:-$defaut}"
}
demander_secret() {
  local question="$1" reponse=""
  if [ "${AKAMANA_NONINTERACTIVE:-0}" = "1" ] || [ ! -r /dev/tty ]; then
    printf ''; return
  fi
  printf '  %s (vide = généré) : ' "$question" > /dev/tty
  IFS= read -r -s reponse < /dev/tty || true
  printf '\n' > /dev/tty
  printf '%s' "$reponse"
}
confirmer() {
  local question="$1" reponse=""
  if [ "${AKAMANA_NONINTERACTIVE:-0}" = "1" ] || [ ! -r /dev/tty ]; then return 1; fi
  printf '  %s [o/N] : ' "$question" > /dev/tty
  IFS= read -r reponse < /dev/tty || true
  [[ "$reponse" =~ ^[oOyY]$ ]]
}

# ── Secrets ──────────────────────────────────────────────────────────────
# openssl est là sur presque toutes les machines ; /dev/urandom sinon.
aleatoire_hex()    { if command -v openssl >/dev/null; then openssl rand -hex "$1"; else od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; fi; }
aleatoire_base64() { if command -v openssl >/dev/null; then openssl rand -base64 "$1"; else head -c "$1" /dev/urandom | base64 | tr -d '\n'; fi; }
# Mot de passe : lettres et chiffres seulement, 24 caractères — copiable
# sans surprise d'échappement, et bien au-delà du minimum de 15 exigé.
# head borne la lecture EN AMONT : avec pipefail, un `tr < /dev/urandom | head`
# meurt d'un SIGPIPE quand head ferme le tube, et set -e arrête le script.
mot_de_passe() { head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-24; }

# ── 1. Docker ────────────────────────────────────────────────────────────
titre "Akamana — installation"

if ! command -v docker >/dev/null 2>&1; then
  avert "Docker n'est pas installé."
  if [ -f /etc/debian_version ] && confirmer "L'installer maintenant avec le script officiel get.docker.com ?"; then
    curl -fsSL https://get.docker.com | sh
    if [ "$(id -u)" != "0" ]; then
      sudo usermod -aG docker "$USER" || true
      avert "Votre compte a été ajouté au groupe docker : ouvrez une nouvelle session, puis relancez ce script."
      exit 0
    fi
  else
    erreur "Installez Docker (https://docs.docker.com/engine/install/) puis relancez."
  fi
fi
docker compose version >/dev/null 2>&1 || erreur "Le plugin Docker Compose manque (docker-compose-plugin)."
docker info >/dev/null 2>&1 || erreur "Docker est installé mais inaccessible : le démon tourne-t-il, et votre compte est-il dans le groupe docker ?"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?') et Compose sont prêts"

# ── 2. Répertoire et téléchargement ──────────────────────────────────────
titre "Emplacement"
DIR="${AKAMANA_DIR:-$(demander "Répertoire d'installation" "$HOME/akamana")}"
DIR="${DIR/#\~/$HOME}"
mkdir -p "$DIR"
cd "$DIR"

if [ -f "$DIR/src/docker-compose.yml" ]; then
  info "Installation existante détectée — mise à jour du code, configuration conservée."
fi
info "Téléchargement de ${DEPOT}@${BRANCHE}…"
rm -rf "$DIR/src.new" && mkdir -p "$DIR/src.new"
curl -fsSL "$ARCHIVE" | tar -xz -C "$DIR/src.new" --strip-components=1 \
  || erreur "Téléchargement impossible : $ARCHIVE"
rm -rf "$DIR/src" && mv "$DIR/src.new" "$DIR/src"
ok "Code dans $DIR/src"

CONFIG_DIR="$DIR/config"; DATA_DIR="$DIR/data"
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR"

# ── 3. Configuration ─────────────────────────────────────────────────────
ENV_APP="$CONFIG_DIR/akamana.env"
ENV_COMPOSE="$DIR/src/.env"

if [ -f "$ENV_APP" ]; then
  ok "Configuration existante conservée : $ENV_APP"
  PORT=$(grep -E '^AKAMANA_HTTP_PORT=' "$ENV_COMPOSE" 2>/dev/null | cut -d= -f2)
  PORT="${PORT:-8081}"
  ADMIN_USER=$(grep -E '^BOOTSTRAP_ADMIN_USERNAME=' "$ENV_APP" | cut -d= -f2)
  MDP_GENERE=""
else
  titre "Configuration"
  PORT="${AKAMANA_HTTP_PORT:-$(demander "Port HTTP à exposer" "8081")}"
  ADMIN_USER="${AKAMANA_ADMIN_USER:-$(demander "Nom du compte administrateur" "admin")}"
  ADMIN_PASS="${AKAMANA_ADMIN_PASSWORD:-$(demander_secret "Mot de passe administrateur, 15 caractères minimum")}"
  MDP_GENERE=""
  if [ -z "$ADMIN_PASS" ]; then ADMIN_PASS="$(mot_de_passe)"; MDP_GENERE="oui"; fi
  [ "${#ADMIN_PASS}" -ge 15 ] || erreur "Le mot de passe administrateur doit faire au moins 15 caractères."
  URL_PUBLIQUE="${AKAMANA_PUBLIC_URL:-$(demander "URL publique (pour les origines autorisées)" "http://localhost:${PORT}")}"

  info "Génération des secrets…"
  JWT_SECRET="$(aleatoire_hex 32)"
  KEK_B64="$(aleatoire_base64 32)"
  DB_PASS="$(mot_de_passe)"
  DB_ROOT_PASS="$(mot_de_passe)"

  # Le fichier lu par le conteneur. Écrit d'un bloc, droits 600 : aucun
  # secret ne passe par la ligne de commande ni par l'historique du shell.
  umask 077
  cat > "$ENV_APP" <<EOF
# Akamana — généré par install.sh le $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Ce fichier contient des secrets. Ne le partagez pas, sauvegardez-le : sans
# KEY_ENCRYPTION_KEY_B64, les clés privées stockées sont irrécupérables.
BIND_ADDR=127.0.0.1:18080
RUST_LOG=info
DATABASE_URL=mysql://akamana:${DB_PASS}@mariadb:3306/akamana
AUTH_MODE=local
JWT_SECRET=${JWT_SECRET}
JWT_EXP_MINUTES=30
KEY_ENCRYPTION_KEY_B64=${KEK_B64}
ROOT_COMMON_NAME=Akamana Root CA
ROOT_VALID_YEARS=10
ALLOWED_ORIGINS=${URL_PUBLIQUE}
BOOTSTRAP_ADMIN_USERNAME=${ADMIN_USER}
BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
AKAMANA_DATA_DIR=/data
ADDONS_DIR=/data/addons
EOF
  ok "Configuration écrite : $ENV_APP (droits 600)"
fi

# Variables lues par docker compose lui-même (ports, chemins, MariaDB).
if [ ! -f "$ENV_COMPOSE" ]; then
  umask 077
  cat > "$ENV_COMPOSE" <<EOF
AKAMANA_HTTP_PORT=${PORT}
AKAMANA_HOST_CONFIG_DIR=${CONFIG_DIR}
AKAMANA_HOST_DATA_DIR=${DATA_DIR}
MARIADB_PASSWORD=${DB_PASS:-}
MARIADB_ROOT_PASSWORD=${DB_ROOT_PASS:-}
EOF
fi
cp -rn "$DIR/src/addons" "$DATA_DIR/" 2>/dev/null || true

# ── 4. Lancement ─────────────────────────────────────────────────────────
titre "Lancement"
info "Construction de l'image — la première fois, la compilation Rust prend 10 à 20 minutes."
if [ "${AKAMANA_DRY_RUN:-0}" = "1" ]; then
  avert "AKAMANA_DRY_RUN=1 : conteneurs non lancés."
  exit 0
fi
( cd "$DIR/src" && docker compose up -d --build )

info "Attente de l'application…"
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    ok "Akamana répond"
    break
  fi
  sleep 3
done
curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1 \
  || avert "Pas encore de réponse sur le port ${PORT}. Regardez : cd $DIR/src && docker compose logs -f akamana"

# ── 5. Résumé ────────────────────────────────────────────────────────────
titre "Terminé"
printf '  URL          : %shttp://localhost:%s%s\n' "$GRAS" "$PORT" "$FIN"
printf '  Compte       : %s\n' "$ADMIN_USER"
if [ -n "$MDP_GENERE" ]; then
  printf '  Mot de passe : %s%s%s   (généré — il est aussi dans %s)\n' "$GRAS" "$ADMIN_PASS" "$FIN" "$ENV_APP"
else
  printf '  Mot de passe : celui que vous avez saisi (dans %s)\n' "$ENV_APP"
fi
printf '\n  Configuration : %s\n  Données       : %s\n' "$CONFIG_DIR" "$DATA_DIR"
printf '  Mettre à jour : relancez cette même commande.\n'
printf '  Arrêter       : cd %s/src && docker compose down\n\n' "$DIR"
