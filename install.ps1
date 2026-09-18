# Akamana — installation en une commande (Windows, PowerShell 5.1 ou 7+).
#
#   irm https://raw.githubusercontent.com/Apalala-sprl/Akamana/main/install.ps1 | iex
#
# Même parcours que install.sh :
#   1. vérifie Docker Desktop et Docker Compose ;
#   2. télécharge le dépôt dans le répertoire choisi — pas besoin de git ;
#   3. pose les quelques questions utiles (répertoire, port, compte admin) ;
#   4. génère des secrets forts avec le générateur cryptographique de .NET ;
#   5. écrit la configuration — jamais affichée, jamais dans l'historique —
#      et lance les conteneurs ;
#   6. attend que l'application réponde, puis dit où la trouver.
#
# Relancer sur une installation existante garde la configuration et se
# contente de mettre à jour et relancer.
#
# Variables d'environnement pour un déroulement sans question :
#   AKAMANA_DIR, AKAMANA_HTTP_PORT, AKAMANA_ADMIN_USER, AKAMANA_ADMIN_PASSWORD,
#   AKAMANA_PUBLIC_URL, AKAMANA_NONINTERACTIVE=1

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Depot    = if ($env:AKAMANA_REPO)   { $env:AKAMANA_REPO }   else { 'Apalala-sprl/Akamana' }
$Branche  = if ($env:AKAMANA_BRANCH) { $env:AKAMANA_BRANCH } else { 'main' }
$Archive  = "https://github.com/$Depot/archive/refs/heads/$Branche.zip"
$NonInteractif = ($env:AKAMANA_NONINTERACTIVE -eq '1')

function Titre($t)  { Write-Host "`n$t" -ForegroundColor White }
function Ok($t)     { Write-Host "  ✓ $t" -ForegroundColor Green }
function Info($t)   { Write-Host "  · $t" }
function Avert($t)  { Write-Host "  ! $t" -ForegroundColor Yellow }
function Erreur($t) { Write-Host "  ✗ $t" -ForegroundColor Red; exit 1 }

function Demander($question, $defaut) {
  if ($NonInteractif) { return $defaut }
  $r = Read-Host "  $question [$defaut]"
  if ([string]::IsNullOrWhiteSpace($r)) { $defaut } else { $r }
}
function DemanderSecret($question) {
  if ($NonInteractif) { return '' }
  $s = Read-Host "  $question (vide = généré)" -AsSecureString
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

# ── Secrets : générateur cryptographique, jamais Get-Random ─────────────
function OctetsAleatoires([int]$n) {
  $b = New-Object byte[] $n
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  $b
}
function AleatoireHex([int]$n)    { -join ((OctetsAleatoires $n) | ForEach-Object { $_.ToString('x2') }) }
function AleatoireBase64([int]$n) { [Convert]::ToBase64String((OctetsAleatoires $n)) }
function MotDePasse {
  # Lettres et chiffres, 24 caractères : copiable sans surprise, > 15 requis.
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  -join ((OctetsAleatoires 24) | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

# ── 1. Docker ────────────────────────────────────────────────────────────
Titre 'Akamana — installation'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Avert "Docker n'est pas installé."
  Erreur 'Installez Docker Desktop (https://docs.docker.com/desktop/setup/install/windows-install/), lancez-le, puis relancez cette commande.'
}
& docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Erreur 'Docker Compose est absent : mettez Docker Desktop à jour.' }
& docker info *> $null
if ($LASTEXITCODE -ne 0) { Erreur 'Docker est installé mais ne répond pas : Docker Desktop est-il démarré ?' }
Ok 'Docker et Compose sont prêts'

# ── 2. Répertoire et téléchargement ──────────────────────────────────────
Titre 'Emplacement'
$Dir = if ($env:AKAMANA_DIR) { $env:AKAMANA_DIR } else { Demander "Répertoire d'installation" (Join-Path $HOME 'akamana') }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$Dir = (Resolve-Path $Dir).Path

if (Test-Path (Join-Path $Dir 'src\docker-compose.yml')) {
  Info 'Installation existante détectée — mise à jour du code, configuration conservée.'
}
Info "Téléchargement de $Depot@$Branche…"
$zip = Join-Path $env:TEMP 'akamana-src.zip'
$tmp = Join-Path $env:TEMP 'akamana-src'
Invoke-WebRequest -Uri $Archive -OutFile $zip -UseBasicParsing
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$extrait = Get-ChildItem $tmp | Select-Object -First 1
$src = Join-Path $Dir 'src'
if (Test-Path $src) { Remove-Item -Recurse -Force $src }
Move-Item $extrait.FullName $src
Remove-Item -Force $zip
Ok "Code dans $src"

$ConfigDir = Join-Path $Dir 'config'
$DataDir   = Join-Path $Dir 'data'
New-Item -ItemType Directory -Force -Path $ConfigDir, $DataDir | Out-Null

# ── 3. Configuration ─────────────────────────────────────────────────────
$EnvApp     = Join-Path $ConfigDir 'akamana.env'
$EnvCompose = Join-Path $src '.env'
$MdpGenere  = $false

if (Test-Path $EnvApp) {
  Ok "Configuration existante conservée : $EnvApp"
  $Port = (Select-String -Path $EnvCompose -Pattern '^AKAMANA_HTTP_PORT=(.*)$' -ErrorAction SilentlyContinue).Matches.Groups[1].Value
  if (-not $Port) { $Port = '8081' }
  $AdminUser = (Select-String -Path $EnvApp -Pattern '^BOOTSTRAP_ADMIN_USERNAME=(.*)$').Matches.Groups[1].Value
} else {
  Titre 'Configuration'
  $Port      = if ($env:AKAMANA_HTTP_PORT) { $env:AKAMANA_HTTP_PORT } else { Demander 'Port HTTP à exposer' '8081' }
  $AdminUser = if ($env:AKAMANA_ADMIN_USER) { $env:AKAMANA_ADMIN_USER } else { Demander 'Nom du compte administrateur' 'admin' }
  $AdminPass = if ($env:AKAMANA_ADMIN_PASSWORD) { $env:AKAMANA_ADMIN_PASSWORD } else { DemanderSecret 'Mot de passe administrateur, 15 caractères minimum' }
  if ([string]::IsNullOrEmpty($AdminPass)) { $AdminPass = MotDePasse; $MdpGenere = $true }
  if ($AdminPass.Length -lt 15) { Erreur 'Le mot de passe administrateur doit faire au moins 15 caractères.' }
  $UrlPublique = if ($env:AKAMANA_PUBLIC_URL) { $env:AKAMANA_PUBLIC_URL } else { Demander 'URL publique (pour les origines autorisées)' "http://localhost:$Port" }

  Info 'Génération des secrets…'
  $JwtSecret  = AleatoireHex 32
  $KekB64     = AleatoireBase64 32
  $DbPass     = MotDePasse
  $DbRootPass = MotDePasse
  $horodatage = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

  # Écrit en UTF-8 sans BOM et en fins de ligne LF : le fichier est lu par
  # un conteneur Linux, un BOM casserait la première variable.
  $contenu = @"
# Akamana — généré par install.ps1 le $horodatage.
# Ce fichier contient des secrets. Ne le partagez pas, sauvegardez-le : sans
# KEY_ENCRYPTION_KEY_B64, les clés privées stockées sont irrécupérables.
BIND_ADDR=127.0.0.1:18080
RUST_LOG=info
DATABASE_URL=mysql://akamana:$DbPass@mariadb:3306/akamana
AUTH_MODE=local
JWT_SECRET=$JwtSecret
JWT_EXP_MINUTES=30
KEY_ENCRYPTION_KEY_B64=$KekB64
ROOT_COMMON_NAME=Akamana Root CA
ROOT_VALID_YEARS=10
ALLOWED_ORIGINS=$UrlPublique
BOOTSTRAP_ADMIN_USERNAME=$AdminUser
BOOTSTRAP_ADMIN_PASSWORD=$AdminPass
AKAMANA_DATA_DIR=/data
ADDONS_DIR=/data/addons
"@ -replace "`r`n", "`n"
  [IO.File]::WriteAllText($EnvApp, $contenu, (New-Object System.Text.UTF8Encoding $false))
  # Lecture réservée au compte courant.
  icacls $EnvApp /inheritance:r /grant:r "$($env:USERNAME):(R,W)" *> $null
  Ok "Configuration écrite : $EnvApp (accès restreint à $($env:USERNAME))"
}

if (-not (Test-Path $EnvCompose)) {
  # Chemins en barres obliques : Docker Desktop les comprend, et compose
  # n'a pas à interpréter des antislashs.
  $cfg = $ConfigDir -replace '\\', '/'
  $dat = $DataDir   -replace '\\', '/'
  $compose = @"
AKAMANA_HTTP_PORT=$Port
AKAMANA_HOST_CONFIG_DIR=$cfg
AKAMANA_HOST_DATA_DIR=$dat
MARIADB_PASSWORD=$DbPass
MARIADB_ROOT_PASSWORD=$DbRootPass
"@ -replace "`r`n", "`n"
  [IO.File]::WriteAllText($EnvCompose, $compose, (New-Object System.Text.UTF8Encoding $false))
}
$addonsSrc = Join-Path $src 'addons'
if ((Test-Path $addonsSrc) -and -not (Test-Path (Join-Path $DataDir 'addons'))) { Copy-Item -Recurse $addonsSrc $DataDir }

# ── 4. Lancement ─────────────────────────────────────────────────────────
Titre 'Lancement'
Info "Construction de l'image — la première fois, la compilation Rust prend 10 à 20 minutes."
if ($env:AKAMANA_DRY_RUN -eq '1') { Avert 'AKAMANA_DRY_RUN=1 : conteneurs non lancés.'; exit 0 }
Push-Location $src
try { & docker compose up -d --build; if ($LASTEXITCODE -ne 0) { Erreur 'docker compose a échoué — voir les messages ci-dessus.' } }
finally { Pop-Location }

Info "Attente de l'application…"
$repond = $false
for ($i = 0; $i -lt 60 -and -not $repond; $i++) {
  try { Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 3 | Out-Null; $repond = $true }
  catch { Start-Sleep -Seconds 3 }
}
if ($repond) { Ok 'Akamana répond' } else { Avert "Pas encore de réponse sur le port $Port. Regardez : cd $src ; docker compose logs -f akamana" }

# ── 5. Résumé ────────────────────────────────────────────────────────────
Titre 'Terminé'
Write-Host "  URL          : http://localhost:$Port" -ForegroundColor White
Write-Host "  Compte       : $AdminUser"
if ($MdpGenere) { Write-Host "  Mot de passe : $AdminPass   (généré — il est aussi dans $EnvApp)" -ForegroundColor White }
else            { Write-Host "  Mot de passe : celui que vous avez saisi (dans $EnvApp)" }
Write-Host "`n  Configuration : $ConfigDir`n  Données       : $DataDir"
Write-Host "  Mettre à jour : relancez cette même commande."
Write-Host "  Arrêter       : cd $src ; docker compose down`n"
