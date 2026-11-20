# Revue de sécurité et modèle de menaces — Akamana

> Revue du 20 novembre 2026, sur la branche `master` (version 0.6.0).
> Périmètre : backend Rust/Axum (`backend/`), interface web statique (`web/`),
> chaîne de déploiement (`deploy/`, `.gitea/`), configuration d'exécution.
> Le modèle de menaces lisible par OWASP Threat Dragon est
> [`threat-model-akamana.json`](threat-model-akamana.json) — à ouvrir dans
> Threat Dragon (bureau ou <https://www.threatdragon.com>), *Open existing
> model* ; le tableau ci-dessous en est la projection.
> Revue précédente : [`../owasp_security_review.md`](../owasp_security_review.md)
> (mars 2026, ASVS 5.0) — ses constats sont pour l'essentiel traités ; ce
> document-ci fait foi pour l'état courant.

## 1. Ce que la revue a trouvé

Deux défauts critiques, tous deux corrigés dans la foulée :

1. **L'export de clé privée n'était protégé par aucun contrôle d'accès.**
   `GET /certificates/tls/:id/export/private` et son équivalent SSH ne
   vérifiaient que le drapeau `allow_private_key_export` de la ligne. Tout
   porteur d'un jeton d'API — quel que soit son scope, y compris un simple
   `ca:read` — et tout compte `auditor` (en lecture seule par définition)
   pouvait donc télécharger les clés privées marquées exportables. Aucune
   trace d'audit n'était écrite. Au total **23 handlers** n'appliquaient
   aucun contrôle de rôle ni de scope, dont la lecture de tout l'inventaire
   des machines et des réglages contenant des URL de webhook (qui portent
   souvent un jeton dans leur chemin).

2. **La clé d'hôte SSH n'était pas vérifiée.** `check_server_key` renvoyait
   `Ok(true)` dans les deux chemins SSH (déploiement et envoi des
   sauvegardes). Un intercepteur sur le réseau — DNS détourné, ARP
   empoisonné — recevait la clé privée du certificat déployé *et* se faisait
   présenter l'identifiant SSH d'Akamana (clé privée ou mot de passe), donc
   l'accès à tout le parc géré.

Quatre points moyens ont été corrigés en même temps (XSS stockées, profil
accessible aux jetons, data URL non validée, traçabilité des exports).

Ce qui tient bien, par ailleurs : aucune `unwrap()` dans le code de
production (lints `deny`), requêtes SQL systématiquement paramétrées,
échappement shell correct côté déploiement, mots de passe en Argon2, jetons
d'API hachés en SHA-256, en-têtes de sécurité et CSP stricte sur les scripts,
verrouillage de compte après 8 échecs, et des messages de validation qui ne
recopient jamais la valeur soumise.

## 2. Corrections appliquées

| # | Correctif | Fichiers | Effet |
|---|-----------|----------|-------|
| 1 | Autorisation sur 23 handlers : `authorize(scope, rôle)` pour les lectures TLS/SSH/CA, `require_human` + `full_admin` pour les réglages | `backend/src/routes/api.rs` | Un jeton d'API ne sort plus du périmètre de ses scopes |
| 2 | Export de clé privée : humain + `can_manage_tls` / `can_manage_ssh`, et ligne d'audit `tls.export_private_key` / `ssh.export_private_key` | `backend/src/routes/api.rs` | Plus d'export par jeton ni par auditeur ; l'acte est tracé |
| 3 | Épinglage TOFU de la clé d'hôte SSH, vérifié **avant** l'authentification, avec endpoints d'administration des épingles | `backend/src/ssh_hostkey.rs`, `deploy.rs`, `backup_remote.rs`, migration `028` | Un hôte dont la clé change est refusé sans qu'aucun secret ne parte |
| 4 | XSS stockées : noms de CA, listes propriétaires/environnements, scopes, types de tâche rendus par `createElement`/`textContent` | `web/app.js` | Plus d'injection de balisage via un champ enregistré |
| 5 | Photo de profil : `data:` restreinte à `data:image/`, endpoints de profil réservés aux humains | `backend/src/routes/api.rs` | Plus de contenu actif stocké, plus de lecture d'historique par un jeton |

## 3. Registre des menaces (STRIDE)

Une menace par ligne, triée : ouvertes d'abord, par gravité décroissante.
`Traitée` signifie qu'une mesure est en place aujourd'hui — la colonne
*Mesure* en nomme aussi les limites quand il en reste.

| № | Élément | STRIDE | Gravité | Statut | Menace | Mesure |
|---|---------|--------|---------|--------|--------|--------|
| 25 | Fichier d'environnement (KEK, JWT) | I — Divulgation | Critique | Ouverte | **KEK et base au même endroit** — Le chiffrement des clés privées ne protège que contre le vol de la base seule : la KEK est sur le même hôte, en clair. | À faire : coffre externe (Vault, KMS, HSM) ou au minimum déverrouillage manuel au démarrage. Mesure immédiate : droits 0600, rotation après toute exposition. |
| 3 | Opérateur (navigateur) | E — Élévation | Élevée | Ouverte | **Poste de l'opérateur compromis** — Un poste infecté dispose de la session et peut exporter toute clé privée exportable. | À faire : limiter la durée de session (JWT_EXP_MINUTES court), demander une re-authentification pour l'export de clé privée, et journaliser l'export (fait). |
| 5 | Automatisation (jeton API) | S — Usurpation | Élevée | Ouverte | **Fuite d'un jeton dans un journal de CI** — Un jeton collé dans une variable de pipeline ou un journal reste valable jusqu'à révocation manuelle. | À faire : date d'expiration obligatoire à la création, et alerte sur jeton inutilisé depuis N jours. Déjà en place : hachage SHA-256 en base, scopes plafonnés par le rôle du créateur, révocation immédiate. |
| 7 | Administrateur système (hôte) | I — Divulgation | Élevée | Ouverte | **Lecture directe de la KEK et du JWT_SECRET** — config/akamana.env contient KEY_ENCRYPTION_KEY_B64 et JWT_SECRET en clair : qui a le shell de l'hôte déchiffre toutes les clés privées et forge des sessions. | À faire : sortir la KEK vers un HSM ou un coffre (Vault/KMS), à défaut restreindre le fichier (0600, propriétaire dédié) et surveiller sa lecture. Rotation du JWT_SECRET et du mot de passe admin après toute exposition. |
| 26 | Sauvegardes (.ezbak) | I — Divulgation | Élevée | Ouverte | **Sauvegarde non chiffrée poussée hors de l'hôte** — Le chiffrement dépend d'une passphrase ou d'un destinataire RSA configurés : sans eux, le dump part en clair. | À faire : refuser l'envoi distant tant qu'aucun destinataire ni passphrase n'est configuré. |
| 8 | nginx (terminaison TLS) | D — Déni de service | Moyenne | Ouverte | **Déni de service sur la façade** — Aucune limite de débit globale : un flot de requêtes authentifiées ou non sature le backend et la base. | À faire : limit_req nginx par IP, et un garde-fou applicatif (tower-governor) sur /api/. En place : verrouillage de compte après 8 échecs de connexion en 15 minutes. |
| 11 | auth_guard + extracteur | S — Usurpation | Moyenne | Ouverte | **Rejeu d'un jeton de session volé** — Un JWT reste valable jusqu'à expiration, sans liste de révocation. | À faire : identifiant de session en base révocable (déconnexion de tous les appareils). En place : /api/v1/session permet au front de détecter une session morte, durée de vie configurable. |
| 15 | API Akamana (Axum) | I — Divulgation | Moyenne | Ouverte | **SSRF par URL de webhook** — Les webhooks de notification, de supervision et SIEM sont des URL libres : le backend les appelle depuis l'intérieur du réseau. | Limité à full_admin aujourd'hui. À faire : refuser les adresses locales/link-local et les schémas autres que https. |
| 20 | Déploiement SSH/SFTP | E — Élévation | Moyenne | Ouverte | **Élévation via la commande de rechargement** — La commande passe entière par sudo -n sh -c sur l'hôte distant, avec les droits du sudoers. | À faire : liste blanche de commandes par application, et sudoers distant restreint à ces commandes. |
| 22 | MariaDB — clés, utilisateurs | T — Altération | Moyenne | Ouverte | **Altération silencieuse d'une ligne** — Un accès direct à la base modifie un certificat ou un rôle sans trace applicative. | À faire : compte MariaDB applicatif sans DROP/ALTER, et scellement du journal d'audit (chaînage par empreinte). |
| 24 | Journal d'audit + accès | R — Répudiation | Moyenne | Ouverte | **Effacement des traces par un full_admin** — Un administrateur compromis peut purger le journal depuis la base. | À faire : export continu vers le SIEM (webhook déjà présent) et chaînage par empreinte pour détecter une coupure. |
| 28 | Hôte géré (nginx, Apache…) | I — Divulgation | Moyenne | Ouverte | **Clé privée laissée dans un répertoire de transit** — Le déploiement passe par un répertoire de transit avant élévation. | À faire : effacement systématique du fichier de transit en fin de tâche, y compris en cas d'échec, et umask strict. |
| 31 | SQL paramétré | I — Divulgation | Moyenne | Ouverte | **Trafic base en clair dans le réseau Docker** — La connexion MariaDB n'impose pas TLS : un conteneur voisin compromis peut écouter. | À faire : TLS sur la connexion MariaDB, ou réseau Docker dédié et isolé. |
| 18 | Tâches de fond | R — Répudiation | Faible | Ouverte | **Tâche de fond sans identité** — Les actions automatiques apparaissent au journal sans acteur distinct. | À faire : acteur « system » explicite dans audit_logs pour chaque tâche. |
| 33 | Sonde TLS (supervision) | I — Divulgation | Faible | Ouverte | **Supervision utilisée comme scanner interne** — Un opérateur peut faire sonder n'importe quelle adresse par le serveur. | À faire : restreindre les cibles aux machines de l'inventaire. |
| 4 | Automatisation (jeton API) | E — Élévation | Critique | Traitée | **Jeton d'API détourné de ses scopes** — Les points de lecture de certificats et surtout l'export de clé privée n'appelaient aucun contrôle : un jeton de n'importe quel scope téléchargeait les clés privées exportables et l'inventaire complet. | Corrigé : chaque lecture appelle authorize(scope, rôle) ; l'export de clé privée exige désormais un humain et un rôle de gestion, et laisse une trace d'audit. |
| 12 | API Akamana (Axum) | E — Élévation | Critique | Traitée | **Contrôle de rôle oublié dans un handler** — Le RBAC n'est pas centralisé : il est écrit à la main dans chaque handler. 23 handlers n'en avaient aucun, dont l'export de clé privée TLS et SSH, lisibles par un auditeur ou par tout jeton d'API. | Corrigé sur les 23 handlers. À faire : rendre l'oubli impossible — extracteur typé par rôle/scope, ou test qui parcourt le routeur et échoue sur tout handler sans garde. |
| 19 | Déploiement SSH/SFTP | S — Usurpation | Critique | Traitée | **Interception de la connexion SSH (clé d'hôte non vérifiée)** — check_server_key acceptait toute clé : un intercepteur recevait la clé privée du certificat déployé et, pire, l'identifiant SSH (clé privée ou mot de passe) d'Akamana. | Corrigé : épinglage TOFU (table ssh_host_keys). La vérification a lieu après l'échange de clés et avant l'authentification ; un changement de clé refuse la connexion sans rien envoyer. Retrait d'une épingle réservé au full_admin et tracé. |
| 32 | SSH : certificat + clé | I — Divulgation | Critique | Traitée | **Clé privée envoyée au mauvais hôte** — Sans épinglage de clé d'hôte, un usurpateur recevait la clé privée du certificat. | Épinglage TOFU vérifié avant authentification (ssh_host_keys). |
| 1 | Opérateur (navigateur) | S — Usurpation | Élevée | Traitée | **Vol de session par XSS stockée** — Le jeton de session vit dans sessionStorage : tout script injecté dans la page le lit et agit en tant qu'opérateur. Des champs enregistrés (nom de CA, listes propriétaires/environnements, type de tâche) étaient interpolés en HTML via innerHTML. | Corrigé : ces rendus passent par createElement/textContent. CSP 'script-src self' sans 'unsafe-inline'. Reste à faire : passer le jeton en cookie HttpOnly+SameSite pour qu'un script ne puisse plus le lire. |
| 10 | auth_guard + extracteur | E — Élévation | Élevée | Traitée | **Contournement par la liste d'exemption** — Tout /api/v1/auth/ est exempté de jeton : un point ajouté sous ce préfixe sans credential propre serait public. | Chaque point exempté porte son propre facteur (mot de passe, jeton MFA à audience akamana-mfa, jeton de réinitialisation à usage unique). À faire : un test d'intégration qui énumère les routes exemptées. |
| 13 | API Akamana (Axum) | T — Altération | Élevée | Traitée | **Injection SQL** — Les requêtes sont construites à l'exécution (pas de macros vérifiées à la compilation). | Toutes les valeurs passent par .bind() ; la seule interpolation de requête porte sur un nom de table issu d'un tableau littéral. |
| 14 | API Akamana (Axum) | T — Altération | Élevée | Traitée | **Injection de commande sur l'hôte distant** — Les chemins et commandes de déploiement, saisis par un opérateur, finissent dans un shell distant via sudo -n sh -c. | Chaque argument passe par shell_quote (guillemets simples POSIX). À faire : restreindre les commandes de rechargement à une liste blanche par application. |
| 16 | API Akamana (Axum) | I — Divulgation | Élevée | Traitée | **Dévoilement du mot de passe dans une erreur de validation** — Le crate validator sérialisait la valeur soumise dans le message d'erreur. | message_validation() reconstruit les messages sans jamais recopier la valeur. |
| 21 | MariaDB — clés, utilisateurs | I — Divulgation | Élevée | Traitée | **Vol de la base** — Une copie de la base donne les certificats, l'inventaire et les clés privées chiffrées. | Clés privées chiffrées par la KEK hors base, mots de passe en Argon2, jetons d'API en SHA-256. Reste : la KEK sur le même hôte (voir la menace sur le fichier d'environnement). |
| 23 | Journal d'audit + accès | R — Répudiation | Élevée | Traitée | **Répudiation d'un export de clé privée** — L'export d'une clé privée n'écrivait aucune ligne d'audit : impossible de dire qui avait sorti quoi. | Corrigé : tls.export_private_key et ssh.export_private_key sont tracés avec l'acteur et l'objet. |
| 27 | Sauvegardes (.ezbak) | T — Altération | Élevée | Traitée | **Restauration d'une sauvegarde falsifiée** — Une restauration remplace utilisateurs et clés. | Réservée au full_admin, tracée, conteneur authentifié (GCM). À faire : confirmation hors bande pour la restauration. |
| 2 | Opérateur (navigateur) | S — Usurpation | Moyenne | Traitée | **Hameçonnage d'identifiants d'administration** — Un faux portail Akamana capte le mot de passe d'un full_admin. | Passkeys WebAuthn (liées à l'origine, insensibles à l'hameçonnage) et TOTP disponibles ; REQUIRE_MFA force l'enrôlement. Reste à faire : imposer MFA aux comptes full_admin. |
| 6 | Fournisseur OIDC (option) | S — Usurpation | Moyenne | Traitée | **Jeton OIDC accepté d'un émetteur inattendu** — Un jeton signé par un autre émetteur ou une clé révoquée ouvrirait une session. | Validation RS256 contre le JWKS de l'émetteur configuré, avec cache. À faire : contrôle explicite de l'audience et rafraîchissement du JWKS sur rotation de clé. |
| 9 | nginx (terminaison TLS) | S — Usurpation | Moyenne | Traitée | **En-tête x-forwarded-for falsifié** — Une IP cliente falsifiée fausserait le verrouillage par IP et les journaux d'accès. | x-forwarded-for n'est honoré que depuis TRUSTED_PROXY_IPS. |
| 17 | Tâches de fond | T — Altération | Moyenne | Traitée | **Renouvellement automatique abusé** — Une durée de validité héritée sans contrôle produisait des certificats refusés par iOS/macOS (limite de 825 jours). | La durée est bornée à 825 jours au renouvellement, avec avertissement dans l'interface. |
| 30 | HTTPS + Bearer | I — Divulgation | Moyenne | Traitée | **Écoute du trafic d'administration** — Les clés privées exportées transitent par cette connexion. | TLS obligatoire, HSTS preload, cookies/sessions hors HTTP. À faire : mTLS pour l'interface d'administration. |
| 29 | SMTP / webhooks (SIEM, alertes) | I — Divulgation | Faible | Traitée | **Fuite d'information par le canal d'alerte** — Les alertes citent noms d'hôtes et comptes. | Contenu limité aux métadonnées, jamais de clé. Les URL de webhook ne sont plus lisibles que par un full_admin (corrigé). |

### Ce qui change pour les appelants

- **Jetons d'API** : `/crl`, `/ssh/certificates*` et les lectures de
  certificats exigent désormais le scope que `openapi.json` leur attribuait
  déjà (`tls:read`, `ssh:read`, `ca:read`). L'implémentation rejoint sa
  propre documentation ; un jeton correctement cadré n'est pas affecté. Un
  jeton qui lisait hors de ses scopes reçoit maintenant `403` — c'est
  exactement le trou qui est refermé.
- **Export de clé privée** : réservé aux humains des rôles de gestion. Pour
  l'automatisation, la clé est remise une seule fois, à l'émission
  (`POST /keys/tls`) : c'est le chemin prévu, il ne change pas.
- **Rôles humains** : les quatre rôles continuent de *lire* les deux
  inventaires — la séparation TLS/SSH porte sur ce qu'on peut faire. Seuls
  les réglages porteurs d'URL de webhook passent en `full_admin`.
- **Déploiement SSH** : la première connexion à chaque hôte enregistre sa
  clé. Aucun déploiement existant n'est interrompu ; un hôte réinstallé
  après coup est refusé jusqu'au retrait de son épingle dans
  *Paramètres → SSH host keys*.

## 4. Ce qui reste à faire, par ordre de rendement

L'estimation est le temps de mise en œuvre et de vérification, pas le temps
calendaire.

### Rendement immédiat (une demi-journée chacun)

1. **Sortir la KEK de l'hôte.** Aujourd'hui `KEY_ENCRYPTION_KEY_B64` est en
   clair dans `config/akamana.env`, à côté de la base qu'elle protège : qui
   obtient un shell sur s13 déchiffre toutes les clés privées. À défaut d'un
   coffre (Vault, KMS, HSM) : fichier en `0600` appartenant à un compte
   dédié, et alerte sur sa lecture. *Un coffre, c'est 1 à 2 jours ; les
   droits et l'alerte, une heure.*
2. **Interdire la sauvegarde distante non chiffrée.** Refuser l'envoi tant
   qu'aucune passphrase ni destinataire RSA n'est configuré — le code sait
   déjà chiffrer, rien ne l'impose. *2 heures.*
3. **Limiter le débit sur `/api/`.** `limit_req` nginx par IP, plus
   `tower-governor` côté applicatif. Le verrouillage de compte ne protège que
   la connexion, pas le reste de l'API. *3 heures.*
4. **Filtrer les URL de webhook.** Refuser les adresses locales, link-local
   et les schémas autres que `https` : le serveur appelle ces URL depuis
   l'intérieur du réseau. *2 heures.*

### Rendement élevé, chantier court (1 à 3 jours)

5. **Rendre l'oubli de RBAC impossible.** La revue a trouvé 23 handlers sans
   contrôle parce que le contrôle est écrit à la main dans chacun des ~140.
   Deux voies : un extracteur typé (`RequireRole<TlsAdmin>`, `Scoped<"tls:read">`)
   qui déplace la garde dans la signature, ou un test d'intégration qui
   parcourt le routeur et échoue sur toute route dont le handler n'appelle
   aucune garde. L'extracteur est préférable : il rend le défaut
   inexprimable. *2 à 3 jours pour les ~140 routes.*
6. **Jeton de session en cookie `HttpOnly` + `SameSite=Strict`.** Tant que le
   JWT vit dans `sessionStorage`, une seule XSS suffit à prendre la main sur
   la PKI. Demande d'ajouter une protection CSRF (jeton par requête ou
   en-tête personnalisé). *1 à 2 jours.*
7. **Révocation de session.** Un identifiant de session en base, vérifié par
   `auth_guard`, permet de couper une session volée sans attendre son
   expiration — et de proposer « déconnecter tous mes appareils ». *1 jour.*
8. **Sceller le journal d'audit.** Chaînage par empreinte (chaque ligne
   couvre la précédente) et export continu vers le SIEM : un `full_admin`
   compromis ne peut plus effacer ses traces sans que la chaîne le montre.
   *1 jour.*
9. **MFA obligatoire pour `full_admin`.** `REQUIRE_MFA` est global ; le
   rendre inconditionnel pour le rôle qui détient la CA racine. *4 heures.*

### Fond de tiroir, à planifier

10. **TLS sur la connexion MariaDB** et réseau Docker dédié — aujourd'hui le
    trafic base passe en clair entre conteneurs. *4 heures.*
11. **Liste blanche des commandes de rechargement** par application, et
    `sudoers` distant restreint à ces commandes : la commande saisie passe
    entière par `sudo -n sh -c`. *1 jour.*
12. **Effacement garanti du répertoire de transit** sur l'hôte distant, y
    compris quand le déploiement échoue. *3 heures.*
13. **Expiration obligatoire des jetons d'API** et alerte sur jeton dormant.
    *4 heures.*
14. **Supervision restreinte à l'inventaire** : n'autoriser la sonde TLS que
    vers des machines enregistrées, pour qu'elle ne serve pas de scanner
    interne. *2 heures.*
15. **Audience OIDC vérifiée explicitement** et rafraîchissement du JWKS sur
    rotation de clé. *4 heures.*

## 5. Hypothèses du modèle

- L'hôte Docker (`s13`) et son administrateur système sont dans le périmètre
  de confiance : la revue signale ce qu'un accès shell permet, mais ne
  cherche pas à s'en défendre.
- La racine de confiance est la CA racine d'Akamana ; sa compromission est
  un événement de reprise d'activité, pas une menace à atténuer dans
  l'application.
- Le réseau est un LAN d'entreprise, pas l'internet public : l'exposition
  publique d'Akamana changerait la gravité du déni de service et de
  l'énumération de comptes.
- Les sauvegardes `.ezbak` sont considérées aussi sensibles que la base :
  elles contiennent les mêmes clés privées chiffrées.

## 6. Tenir ce document à jour

Le fichier Threat Dragon est la source : le tableau de la section 3 en est
une projection. Après modification du modèle dans Threat Dragon, régénérer
le tableau plutôt que l'éditer à la main. Toute route ajoutée à
`routes::api::router()` doit apparaître dans le modèle si elle touche une
clé, un identifiant ou l'inventaire.
