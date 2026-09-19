use crate::{config::Config, errors::AppError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{Duration, Utc};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Builder, X509Extension, X509Name, X509NameBuilder, X509,
    },
};
use rand::RngCore;
use rand_core::OsRng;
use sqlx::MySqlPool;
use ssh_key::{
    certificate::{Builder as SshCertBuilder, CertType},
    private::PrivateKey as SshPrivateKey,
    public::PublicKey as SshPublicKey,
    Algorithm, Certificate as SshCertificate, HashAlg, LineEnding, Mpint,
};

pub struct TlsMaterial {
    pub serial_hex: String,
    pub cert_pem: String,
    pub private_key_pem: String,
    pub valid_from: chrono::DateTime<Utc>,
    pub valid_to: chrono::DateTime<Utc>,
}

pub struct RootCaMaterial {
    pub cert_pem: String,
    pub private_key_pem: String,
    pub not_before: chrono::DateTime<Utc>,
    pub not_after: chrono::DateTime<Utc>,
}

#[derive(Default, Clone)]
pub struct SubjectDn {
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    pub org_unit: Option<String>,
}

pub struct CreateRootCaParams<'a> {
    pub organization: &'a str,
    pub common_name: &'a str,
    pub description: Option<&'a str>,
    pub valid_years: i64,
    pub cipher: Option<&'a str>,
    pub key_length: Option<i32>,
    pub dn: SubjectDn,
}

pub struct GenerateTlsMaterialParams<'a> {
    pub root_id: i32,
    pub common_name: &'a str,
    pub valid_days: i64,
    pub is_ca: bool,
    pub cipher: Option<&'a str>,
    pub key_length: Option<i32>,
    /// Subject Alternative Names (DNS names and/or IP addresses) the leaf is valid for.
    pub sans: &'a [String],
    /// Extended Key Usage purpose for leaf certs: "server", "client", or "both".
    pub purpose: &'a str,
}

pub struct SshMaterial {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint_sha256: String,
    pub valid_from: chrono::DateTime<Utc>,
    pub valid_to: chrono::DateTime<Utc>,
}

fn encryption_key(cfg: &Config) -> Result<[u8; 32], AppError> {
    let bytes = STANDARD
        .decode(&cfg.key_encryption_key_b64)
        .map_err(|_| AppError::Internal("invalid KEY_ENCRYPTION_KEY_B64".to_string()))?;
    if bytes.len() != 32 {
        return Err(AppError::Internal(
            "KEY_ENCRYPTION_KEY_B64 must decode to exactly 32 bytes".to_string(),
        ));
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn normalize_tls_cipher(cipher: Option<&str>) -> &str {
    match cipher.unwrap_or("ed25519").to_lowercase().as_str() {
        "rsa" => "rsa",
        "ecdsa_p256" => "ecdsa_p256",
        _ => "ed25519",
    }
}

fn sign_digest_for_key(key: &PKey<Private>) -> MessageDigest {
    if key.id() == Id::ED25519 {
        MessageDigest::null()
    } else {
        MessageDigest::sha256()
    }
}

fn generate_tls_keypair(cipher: &str, key_length: i32) -> Result<PKey<Private>, AppError> {
    match cipher {
        "rsa" => {
            let bits = key_length.clamp(2048, 8192) as u32;
            let rsa = Rsa::generate(bits)
                .map_err(|e| AppError::Internal(format!("rsa key generation failed: {e}")))?;
            PKey::from_rsa(rsa)
                .map_err(|e| AppError::Internal(format!("rsa key conversion failed: {e}")))
        }
        "ecdsa_p256" => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                .map_err(|e| AppError::Internal(format!("ecdsa group init failed: {e}")))?;
            let ec = EcKey::generate(&group)
                .map_err(|e| AppError::Internal(format!("ecdsa key generation failed: {e}")))?;
            PKey::from_ec_key(ec)
                .map_err(|e| AppError::Internal(format!("ecdsa key conversion failed: {e}")))
        }
        _ => PKey::generate_ed25519()
            .map_err(|e| AppError::Internal(format!("ed25519 key generation failed: {e}"))),
    }
}

pub fn encrypt_secret(cfg: &Config, plaintext: &str) -> Result<String, AppError> {
    let key = encryption_key(cfg)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("invalid encryption key".to_string()))?;
    let mut nonce_bytes = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| AppError::Internal("unable to encrypt secret".to_string()))?;
    Ok(format!(
        "{}.{}",
        STANDARD.encode(nonce_bytes),
        STANDARD.encode(ciphertext)
    ))
}

pub fn decrypt_secret(cfg: &Config, payload: &str) -> Result<String, AppError> {
    let key = encryption_key(cfg)?;
    let mut parts = payload.split('.');
    let nonce = parts
        .next()
        .ok_or_else(|| AppError::Internal("invalid encrypted payload".to_string()))?;
    let body = parts
        .next()
        .ok_or_else(|| AppError::Internal("invalid encrypted payload".to_string()))?;
    let nonce_vec = STANDARD
        .decode(nonce)
        .map_err(|_| AppError::Internal("invalid nonce payload".to_string()))?;
    let body_vec = STANDARD
        .decode(body)
        .map_err(|_| AppError::Internal("invalid body payload".to_string()))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("invalid encryption key".to_string()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_vec), body_vec.as_ref())
        .map_err(|_| AppError::Internal("unable to decrypt secret".to_string()))?;
    String::from_utf8(plaintext)
        .map_err(|_| AppError::Internal("decrypted secret is not UTF-8".to_string()))
}

/// SHA-256 (hex) of an arbitrary string, for constant-shape storage/lookup of
/// bearer-style secrets (API tokens, password-reset tokens, recovery codes).
/// Uses the already-vendored OpenSSL rather than pulling in a separate `sha2`
/// crate.
pub fn sha256_hex(value: &str) -> String {
    let digest = openssl::sha::sha256(value.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 (hex) of an API token. Kept as its own name because it is the
/// lookup key for the `api_tokens` table.
pub fn hash_api_token(token: &str) -> String {
    sha256_hex(token)
}

/// Mints a new API token. Returns `(full_token, display_prefix, sha256_hex)`.
/// The full token is shown to the operator exactly once; only the hash is stored.
pub fn generate_api_token() -> (String, String, String) {
    let mut bytes = [0_u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let full = format!("ezk_{}", URL_SAFE_NO_PAD.encode(bytes));
    let prefix: String = full.chars().take(12).collect();
    let hash = hash_api_token(&full);
    (full, prefix, hash)
}

/// Seeds a root CA on first start **only when explicitly asked**.
///
/// A certificate authority is not something to conjure behind an operator's
/// back: its subject, key type and validity are policy decisions, and an
/// auto-generated root silently occupying id 1 gets mistaken for the real one.
/// So the default is to start with no CA at all — the operator then imports an
/// existing root (`POST /certificates/root/import`) or creates one with a
/// proper subject (`POST /certificates/root`).
///
/// Setting `AUTO_CREATE_ROOT_CA=true` restores the previous behaviour, which is
/// convenient for throwaway test instances.
pub async fn ensure_root_ca(pool: &MySqlPool, cfg: &Config) -> Result<(), AppError> {
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM root_ca WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    if exists.is_some() {
        return Ok(());
    }

    let auto_create = std::env::var("AUTO_CREATE_ROOT_CA")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "true" || v == "1" || v == "yes"
        })
        .unwrap_or(false);
    if !auto_create {
        tracing::info!(
            "no root CA configured; import one with POST /api/v1/certificates/root/import \
             or create one with POST /api/v1/certificates/root \
             (set AUTO_CREATE_ROOT_CA=true to generate one automatically)"
        );
        return Ok(());
    }

    let root_key = PKey::generate_ed25519()
        .map_err(|e| AppError::Internal(format!("root key generation failed: {e}")))?;
    let root_cert = build_root_ca_cert(
        &root_key,
        &cfg.root_common_name,
        cfg.root_valid_years,
        &SubjectDn::default(),
    )?;
    let cert_pem = String::from_utf8(
        root_cert
            .to_pem()
            .map_err(|e| AppError::Internal(format!("root cert pem export failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("root cert pem utf8 failed: {e}")))?;
    let key_pem = String::from_utf8(
        root_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| AppError::Internal(format!("root key pem export failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("root key pem utf8 failed: {e}")))?;

    let now = Utc::now();
    sqlx::query("INSERT INTO root_ca (id, common_name, cert_pem, private_key_enc, not_before, not_after, created_at) VALUES (1, ?, ?, ?, ?, ?, ?)")
        .bind(&cfg.root_common_name)
        .bind(cert_pem)
        .bind(encrypt_secret(cfg, &key_pem)?)
        .bind(now.naive_utc())
        .bind((now + Duration::days(cfg.root_valid_years * 365)).naive_utc())
        .bind(now.naive_utc())
        .execute(pool)
        .await?;

    Ok(())
}

fn append_name_entry(
    builder: &mut X509NameBuilder,
    nid: Nid,
    value: &Option<String>,
) -> Result<(), AppError> {
    if let Some(v) = value {
        let v = v.trim();
        if !v.is_empty() {
            builder
                .append_entry_by_nid(nid, v)
                .map_err(|e| AppError::Internal(format!("x509 name add failed: {e}")))?;
        }
    }
    Ok(())
}

fn build_subject_with_dn(cn: &str, dn: &SubjectDn) -> Result<X509Name, AppError> {
    let mut name = X509NameBuilder::new()
        .map_err(|e| AppError::Internal(format!("x509 name builder failed: {e}")))?;
    append_name_entry(&mut name, Nid::COUNTRYNAME, &dn.country)?;
    append_name_entry(&mut name, Nid::STATEORPROVINCENAME, &dn.state)?;
    append_name_entry(&mut name, Nid::LOCALITYNAME, &dn.locality)?;
    append_name_entry(&mut name, Nid::ORGANIZATIONNAME, &dn.organization)?;
    append_name_entry(&mut name, Nid::ORGANIZATIONALUNITNAME, &dn.org_unit)?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)
        .map_err(|e| AppError::Internal(format!("x509 CN add failed: {e}")))?;
    Ok(name.build())
}

/// Read the C/ST/L/O/OU fields from an existing certificate's subject so issued
/// certificates can inherit the Root CA's distinguished name.
fn dn_from_cert(cert: &X509) -> SubjectDn {
    let get = |nid: Nid| {
        cert.subject_name()
            .entries_by_nid(nid)
            .next()
            .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
    };
    SubjectDn {
        country: get(Nid::COUNTRYNAME),
        state: get(Nid::STATEORPROVINCENAME),
        locality: get(Nid::LOCALITYNAME),
        organization: get(Nid::ORGANIZATIONNAME),
        org_unit: get(Nid::ORGANIZATIONALUNITNAME),
    }
}

fn build_root_ca_cert(
    root_key: &PKey<Private>,
    cn: &str,
    years: i64,
    dn: &SubjectDn,
) -> Result<X509, AppError> {
    let name = build_subject_with_dn(cn, dn)?;

    let mut builder =
        X509Builder::new().map_err(|e| AppError::Internal(format!("x509 builder failed: {e}")))?;
    builder
        .set_version(2)
        .map_err(|e| AppError::Internal(format!("set x509 version failed: {e}")))?;

    let mut serial_bn =
        BigNum::new().map_err(|e| AppError::Internal(format!("serial bignum init failed: {e}")))?;
    serial_bn
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(|e| AppError::Internal(format!("serial random failed: {e}")))?;
    let serial = Asn1Integer::from_bn(&serial_bn)
        .map_err(|e| AppError::Internal(format!("serial conversion failed: {e}")))?;

    builder
        .set_serial_number(&serial)
        .map_err(|e| AppError::Internal(format!("set serial failed: {e}")))?;
    builder
        .set_subject_name(&name)
        .map_err(|e| AppError::Internal(format!("set subject failed: {e}")))?;
    builder
        .set_issuer_name(&name)
        .map_err(|e| AppError::Internal(format!("set issuer failed: {e}")))?;
    builder
        .set_pubkey(root_key)
        .map_err(|e| AppError::Internal(format!("set pubkey failed: {e}")))?;
    builder
        .set_not_before(
            Asn1Time::days_from_now(0)
                .map_err(|e| AppError::Internal(format!("set not_before failed: {e}")))?
                .as_ref(),
        )
        .map_err(|e| AppError::Internal(format!("apply not_before failed: {e}")))?;
    builder
        .set_not_after(
            Asn1Time::days_from_now((years * 365) as u32)
                .map_err(|e| AppError::Internal(format!("set not_after failed: {e}")))?
                .as_ref(),
        )
        .map_err(|e| AppError::Internal(format!("apply not_after failed: {e}")))?;

    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(|e| AppError::Internal(format!("basic constraints failed: {e}")))?,
        )
        .map_err(|e| AppError::Internal(format!("append basic constraints failed: {e}")))?;
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|e| AppError::Internal(format!("key usage failed: {e}")))?,
        )
        .map_err(|e| AppError::Internal(format!("append key usage failed: {e}")))?;
    let context = builder.x509v3_context(None, None);
    builder
        .append_extension(
            SubjectKeyIdentifier::new()
                .build(&context)
                .map_err(|e| AppError::Internal(format!("subject key id failed: {e}")))?,
        )
        .map_err(|e| AppError::Internal(format!("append subject key id failed: {e}")))?;

    builder
        .sign(root_key, sign_digest_for_key(root_key))
        .map_err(|e| AppError::Internal(format!("sign root cert failed: {e}")))?;
    Ok(builder.build())
}

pub fn build_root_ca_material(
    cn: &str,
    years: i64,
    cipher: Option<&str>,
    key_length: Option<i32>,
    dn: &SubjectDn,
) -> Result<RootCaMaterial, AppError> {
    let normalized_cipher = normalize_tls_cipher(cipher);
    let normalized_key_length = key_length.unwrap_or(if normalized_cipher == "rsa" {
        4096
    } else {
        256
    });
    let root_key = generate_tls_keypair(normalized_cipher, normalized_key_length)
        .map_err(|e| AppError::Internal(format!("root key generation failed: {e}")))?;
    let root_cert = build_root_ca_cert(&root_key, cn, years, dn)?;
    let cert_pem = String::from_utf8(
        root_cert
            .to_pem()
            .map_err(|e| AppError::Internal(format!("root cert pem export failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("root cert pem utf8 failed: {e}")))?;
    let key_pem = String::from_utf8(
        root_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| AppError::Internal(format!("root key pem export failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("root key pem utf8 failed: {e}")))?;
    let not_before = Utc::now();
    let not_after = not_before + Duration::days(years * 365);
    Ok(RootCaMaterial {
        cert_pem,
        private_key_pem: key_pem,
        not_before,
        not_after,
    })
}

pub async fn create_root_ca(
    pool: &MySqlPool,
    cfg: &Config,
    params: CreateRootCaParams<'_>,
) -> Result<i32, AppError> {
    let next_id: Option<(i32,)> = sqlx::query_as("SELECT COALESCE(MAX(id), 0) + 1 FROM root_ca")
        .fetch_optional(pool)
        .await?;
    let root_id = next_id.map(|r| r.0).unwrap_or(1);
    let normalized_cipher = normalize_tls_cipher(params.cipher);
    let normalized_key_length = params.key_length.unwrap_or(if normalized_cipher == "rsa" {
        4096
    } else {
        256
    });
    // The organization from the request is part of the DN used to build the cert.
    let mut dn = params.dn.clone();
    if dn.organization.is_none() && !params.organization.trim().is_empty() {
        dn.organization = Some(params.organization.to_string());
    }
    let material = build_root_ca_material(
        params.common_name,
        params.valid_years,
        Some(normalized_cipher),
        Some(normalized_key_length),
        &dn,
    )?;
    sqlx::query(
        "INSERT INTO root_ca (id, common_name, organization, description, cert_pem, private_key_enc, not_before, not_after, created_at, cipher, key_length, country, state, locality, org_unit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(root_id)
    .bind(params.common_name)
    .bind(params.organization)
    .bind(params.description.unwrap_or(""))
    .bind(material.cert_pem)
    .bind(encrypt_secret(cfg, &material.private_key_pem)?)
    .bind(material.not_before.naive_utc())
    .bind(material.not_after.naive_utc())
    .bind(Utc::now().naive_utc())
    .bind(normalized_cipher)
    .bind(normalized_key_length)
    .bind(&dn.country)
    .bind(&dn.state)
    .bind(&dn.locality)
    .bind(&dn.org_unit)
    .execute(pool)
    .await?;
    Ok(root_id)
}

async fn load_root_material_by_id(
    pool: &MySqlPool,
    cfg: &Config,
    root_id: i32,
) -> Result<(X509, PKey<Private>), AppError> {
    let row: (String, String) =
        sqlx::query_as("SELECT cert_pem, private_key_enc FROM root_ca WHERE id = ?")
            .bind(root_id)
            .fetch_one(pool)
            .await?;

    let cert = X509::from_pem(row.0.as_bytes())
        .map_err(|e| AppError::Internal(format!("load root cert failed: {e}")))?;
    let key_pem = decrypt_secret(cfg, &row.1)?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| AppError::Internal(format!("load root key failed: {e}")))?;
    Ok((cert, key))
}

pub async fn generate_tls_material(
    pool: &MySqlPool,
    cfg: &Config,
    params: GenerateTlsMaterialParams<'_>,
) -> Result<TlsMaterial, AppError> {
    let (root_cert, root_key) = load_root_material_by_id(pool, cfg, params.root_id).await?;
    // Resolve the CDP URL up front (before building the cert) so no non-Send
    // openssl builder is held across this await.
    let cdp_url = crl_cdp_url(pool, params.root_id).await;
    let normalized_cipher = normalize_tls_cipher(params.cipher);
    let normalized_key_length = params.key_length.unwrap_or(if normalized_cipher == "rsa" {
        3072
    } else {
        256
    });
    let key = generate_tls_keypair(normalized_cipher, normalized_key_length)
        .map_err(|e| AppError::Internal(format!("leaf key generation failed: {e}")))?;

    let mut builder =
        X509Builder::new().map_err(|e| AppError::Internal(format!("x509 builder failed: {e}")))?;
    builder
        .set_version(2)
        .map_err(|e| AppError::Internal(format!("set version failed: {e}")))?;

    let mut serial_bn =
        BigNum::new().map_err(|e| AppError::Internal(format!("serial bignum failed: {e}")))?;
    serial_bn
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(|e| AppError::Internal(format!("serial random failed: {e}")))?;
    let serial = Asn1Integer::from_bn(&serial_bn)
        .map_err(|e| AppError::Internal(format!("serial conversion failed: {e}")))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| AppError::Internal(format!("set serial failed: {e}")))?;

    // Inherit the Root CA's distinguished name (C/ST/L/O/OU) for the issued certificate.
    let subject = build_subject_with_dn(params.common_name, &dn_from_cert(&root_cert))?;
    builder
        .set_subject_name(&subject)
        .map_err(|e| AppError::Internal(format!("set subject failed: {e}")))?;
    builder
        .set_issuer_name(root_cert.subject_name())
        .map_err(|e| AppError::Internal(format!("set issuer failed: {e}")))?;
    builder
        .set_pubkey(&key)
        .map_err(|e| AppError::Internal(format!("set leaf pubkey failed: {e}")))?;
    builder
        .set_not_before(
            Asn1Time::days_from_now(0)
                .map_err(|e| AppError::Internal(format!("leaf not_before failed: {e}")))?
                .as_ref(),
        )
        .map_err(|e| AppError::Internal(format!("apply leaf not_before failed: {e}")))?;
    builder
        .set_not_after(
            Asn1Time::days_from_now(params.valid_days as u32)
                .map_err(|e| AppError::Internal(format!("leaf not_after failed: {e}")))?
                .as_ref(),
        )
        .map_err(|e| AppError::Internal(format!("apply leaf not_after failed: {e}")))?;

    builder
        .append_extension(if params.is_ca {
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .map_err(|e| {
                    AppError::Internal(format!("intermediate basic constraints failed: {e}"))
                })?
        } else {
            BasicConstraints::new()
                .critical()
                .build()
                .map_err(|e| AppError::Internal(format!("leaf basic constraints failed: {e}")))?
        })
        .map_err(|e| AppError::Internal(format!("append leaf basic constraints failed: {e}")))?;
    builder
        .append_extension(if params.is_ca {
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .digital_signature()
                .build()
                .map_err(|e| AppError::Internal(format!("intermediate key usage failed: {e}")))?
        } else {
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .map_err(|e| AppError::Internal(format!("leaf key usage failed: {e}")))?
        })
        .map_err(|e| AppError::Internal(format!("append leaf key usage failed: {e}")))?;

    // Leaf-only: Extended Key Usage (mTLS purpose) and Subject Alternative Names.
    if !params.is_ca {
        let mut eku = ExtendedKeyUsage::new();
        match params.purpose {
            "client" => {
                eku.client_auth();
            }
            "both" => {
                eku.server_auth();
                eku.client_auth();
            }
            _ => {
                eku.server_auth();
            }
        }
        builder
            .append_extension(
                eku.build()
                    .map_err(|e| AppError::Internal(format!("eku build failed: {e}")))?,
            )
            .map_err(|e| AppError::Internal(format!("append eku failed: {e}")))?;

        let mut sans: Vec<String> = params
            .sans
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if sans.is_empty() {
            sans.push(params.common_name.to_string());
        }
        let mut san_builder = SubjectAlternativeName::new();
        for s in &sans {
            if s.parse::<std::net::IpAddr>().is_ok() {
                san_builder.ip(s);
            } else {
                san_builder.dns(s);
            }
        }
        let san_ext = {
            let ctx = builder.x509v3_context(Some(&root_cert), None);
            san_builder
                .build(&ctx)
                .map_err(|e| AppError::Internal(format!("san build failed: {e}")))?
        };
        builder
            .append_extension(san_ext)
            .map_err(|e| AppError::Internal(format!("append san failed: {e}")))?;
    }

    let context = builder.x509v3_context(Some(&root_cert), None);
    builder
        .append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .issuer(true)
                .build(&context)
                .map_err(|e| AppError::Internal(format!("authority key id failed: {e}")))?,
        )
        .map_err(|e| AppError::Internal(format!("append authority key id failed: {e}")))?;

    // CRL Distribution Point: embed the URL where this cert's issuer publishes its
    // CRL so clients know where to check revocation. URL is lowercased to avoid
    // case issues on Linux servers.
    if let Some(cdp) = &cdp_url {
        let ctx = builder.x509v3_context(Some(&root_cert), None);
        // The typed CDP builder is not exposed by the openssl crate; the
        // config-string constructor is the supported path here.
        #[allow(deprecated)]
        let ext = X509Extension::new_nid(
            None,
            Some(&ctx),
            Nid::CRL_DISTRIBUTION_POINTS,
            &format!("URI:{cdp}"),
        )
        .map_err(|e| AppError::Internal(format!("crl distribution point failed: {e}")))?;
        builder
            .append_extension(ext)
            .map_err(|e| AppError::Internal(format!("append cdp failed: {e}")))?;
    }

    builder
        .sign(&root_key, sign_digest_for_key(&root_key))
        .map_err(|e| AppError::Internal(format!("leaf sign failed: {e}")))?;
    let cert = builder.build();

    let cert_pem = String::from_utf8(
        cert.to_pem()
            .map_err(|e| AppError::Internal(format!("leaf cert pem failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("leaf cert utf8 failed: {e}")))?;
    let key_pem = String::from_utf8(
        key.private_key_to_pem_pkcs8()
            .map_err(|e| AppError::Internal(format!("leaf key pem failed: {e}")))?,
    )
    .map_err(|e| AppError::Internal(format!("leaf key utf8 failed: {e}")))?;

    let valid_from = Utc::now();
    let valid_to = valid_from + Duration::days(params.valid_days);

    Ok(TlsMaterial {
        serial_hex: serial_bn
            .to_hex_str()
            .map_err(|e| AppError::Internal(format!("serial to hex failed: {e}")))?
            .to_string(),
        cert_pem,
        private_key_pem: key_pem,
        valid_from,
        valid_to,
    })
}

/// What an operator learns about a key they pasted, before storing it.
#[derive(Debug, serde::Serialize)]
pub struct SshKeyAnalysis {
    /// "public", "private" or "pair" — what was actually supplied.
    pub supplied: String,
    /// Wire name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// Short family used by the rest of the app: ed25519, rsa, ecdsa, dsa.
    pub family: String,
    pub bits: Option<u32>,
    pub fingerprint_sha256: String,
    pub comment: Option<String>,
    /// A private key sealed with a passphrase. Readable, but unusable for
    /// unattended deployment until it is decrypted.
    pub encrypted: bool,
    /// Set only when both halves were supplied.
    pub matches_public: Option<bool>,
    /// Blocking problems: the key should not be imported as is.
    pub errors: Vec<String>,
    /// Worth knowing, not blocking.
    pub warnings: Vec<String>,
}

/// Bit length of a multi-precision integer, ignoring leading zero padding.
fn mpint_bits(m: &Mpint) -> u32 {
    let bytes = m.as_positive_bytes().unwrap_or_else(|| m.as_bytes());
    let significant: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    match significant.split_first() {
        None => 0,
        Some((first, rest)) => (rest.len() as u32) * 8 + (8 - first.leading_zeros()),
    }
}

fn describe_key(data: &ssh_key::public::KeyData) -> (String, String, Option<u32>) {
    let algorithm = data.algorithm().as_str().to_string();
    if let Some(rsa) = data.rsa() {
        return ("rsa".to_string(), algorithm, Some(mpint_bits(&rsa.n)));
    }
    if data.is_ed25519() {
        return ("ed25519".to_string(), algorithm, Some(256));
    }
    if let Some(ec) = data.ecdsa() {
        let bits = match ec.curve() {
            ssh_key::EcdsaCurve::NistP256 => 256,
            ssh_key::EcdsaCurve::NistP384 => 384,
            ssh_key::EcdsaCurve::NistP521 => 521,
        };
        return ("ecdsa".to_string(), algorithm, Some(bits));
    }
    if let Some(dsa) = data.dsa() {
        return ("dsa".to_string(), algorithm, Some(mpint_bits(&dsa.p)));
    }
    ("other".to_string(), algorithm, None)
}

/// Judges a key the way an administrator would, so the verdict travels with the
/// import instead of living in someone's head.
fn appraise(family: &str, bits: Option<u32>, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    match family {
        "dsa" => errors.push(
            "DSA keys are obsolete and refused by OpenSSH 7.0 and later; this key will not authenticate anywhere current.".to_string(),
        ),
        "rsa" => match bits {
            Some(b) if b < 2048 => errors.push(format!(
                "RSA {b} bits is below the 2048-bit minimum accepted today and is considered broken."
            )),
            Some(b) if b < 3072 => warnings.push(format!(
                "RSA {b} bits is accepted but no longer generous; 3072 bits or an Ed25519 key would age better."
            )),
            _ => {}
        },
        "ecdsa" => warnings.push(
            "ECDSA depends on the NIST curves and on flawless random number generation at signing time; Ed25519 is the safer default."
                .to_string(),
        ),
        "other" => warnings.push(
            "Unrecognised key type: it can be stored, but this server cannot vouch for its strength.".to_string(),
        ),
        _ => {}
    }
}

/// Parses whatever the operator pasted or uploaded and reports what it is.
///
/// Both halves are optional: a public key alone is enough to authorise access,
/// a private key alone carries its own public half, and supplying both lets us
/// answer the question that actually bites — do these two belong together?
pub fn analyze_ssh_key(
    public_text: Option<&str>,
    private_text: Option<&str>,
) -> Result<SshKeyAnalysis, AppError> {
    let public_text = public_text.map(str::trim).filter(|s| !s.is_empty());
    let private_text = private_text.map(str::trim).filter(|s| !s.is_empty());

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let parsed_private = match private_text {
        Some(text) => Some(SshPrivateKey::from_openssh(text).map_err(|e| {
            // The most common paste failure by far is a PuTTY .ppk, which is a
            // different format entirely rather than a corrupted OpenSSH one.
            let hint = if text.contains("PuTTY-User-Key-File") {
                " This looks like a PuTTY .ppk file; export it with PuTTYgen as \"Export OpenSSH key\" first."
            } else if text.contains("BEGIN RSA PRIVATE KEY") {
                " This is a legacy PEM key; convert it with `ssh-keygen -p -m RFC4716 -f <file>`."
            } else {
                ""
            };
            AppError::Validation(format!("private key could not be parsed: {e}.{hint}"))
        })?),
        None => None,
    };

    let parsed_public = match public_text {
        Some(text) => Some(SshPublicKey::from_openssh(text).map_err(|e| {
            AppError::Validation(format!(
                "public key could not be parsed: {e}. An OpenSSH one-line key is expected, e.g. `ssh-ed25519 AAAA... comment`."
            ))
        })?),
        None => None,
    };

    // The public half of an encrypted private key is stored in clear, so a
    // passphrase never stops us from describing the key.
    let reference: SshPublicKey = match (&parsed_public, &parsed_private) {
        (Some(pubk), _) => pubk.clone(),
        (None, Some(privk)) => privk.public_key().clone(),
        (None, None) => {
            return Err(AppError::Validation(
                "supply a public key, a private key, or both".to_string(),
            ))
        }
    };

    let matches_public = match (&parsed_public, &parsed_private) {
        (Some(pubk), Some(privk)) => Some(
            pubk.fingerprint(HashAlg::Sha256) == privk.public_key().fingerprint(HashAlg::Sha256),
        ),
        _ => None,
    };
    if matches_public == Some(false) {
        errors.push(
            "The private key does not match the public key: they are two different keys."
                .to_string(),
        );
    }

    let encrypted = parsed_private.as_ref().is_some_and(|k| k.is_encrypted());
    if encrypted {
        warnings.push(
            "This private key is protected by a passphrase. Akamana cannot use it for unattended deployment until it is supplied without one."
                .to_string(),
        );
    }

    let (family, algorithm, bits) = describe_key(reference.key_data());
    appraise(&family, bits, &mut errors, &mut warnings);

    let comment = {
        let c = reference.comment().trim();
        if c.is_empty() {
            warnings.push(
                "The key carries no comment; a comment such as an owner or hostname makes it far easier to recognise later."
                    .to_string(),
            );
            None
        } else {
            Some(c.to_string())
        }
    };

    let supplied = match (parsed_public.is_some(), parsed_private.is_some()) {
        (true, true) => "pair",
        (true, false) => "public",
        _ => "private",
    }
    .to_string();

    Ok(SshKeyAnalysis {
        supplied,
        algorithm,
        family,
        bits,
        fingerprint_sha256: reference.fingerprint(HashAlg::Sha256).to_string(),
        comment,
        encrypted,
        matches_public,
        errors,
        warnings,
    })
}

pub fn generate_ssh_material(comment: &str, valid_days: i64) -> Result<SshMaterial, AppError> {
    let private_key = SshPrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| AppError::Internal(format!("ssh key generation failed: {e}")))?;
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| AppError::Internal(format!("ssh public export failed: {e}")))?;
    let private_text = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| AppError::Internal(format!("ssh private export failed: {e}")))?;
    let fingerprint = private_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    let valid_from = Utc::now();
    let valid_to = valid_from + Duration::days(valid_days);
    let public_with_comment = format!("{} {}", public_key, comment);

    Ok(SshMaterial {
        algorithm: "ed25519".to_string(),
        public_key: public_with_comment,
        private_key: private_text.to_string(),
        fingerprint_sha256: fingerprint,
        valid_from,
        valid_to,
    })
}

pub struct SshCaMaterial {
    pub algorithm: String,
    /// OpenSSH public key line (the CA key to distribute via `TrustedUserCAKeys`
    /// or a `@cert-authority` line in `known_hosts`), with the CA name as comment.
    pub public_key: String,
    /// OpenSSH-format encrypted-at-rest-elsewhere private key PEM.
    pub private_key: String,
    pub fingerprint_sha256: String,
}

/// Generates an Ed25519 SSH Certificate Authority keypair. `comment` labels the
/// CA public key (e.g. "Akamana SSH User CA").
pub fn generate_ssh_ca_material(comment: &str) -> Result<SshCaMaterial, AppError> {
    let private_key = SshPrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| AppError::Internal(format!("ssh ca key generation failed: {e}")))?;
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| AppError::Internal(format!("ssh ca public export failed: {e}")))?;
    let private_text = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| AppError::Internal(format!("ssh ca private export failed: {e}")))?;
    let fingerprint = private_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();

    Ok(SshCaMaterial {
        algorithm: "ed25519".to_string(),
        public_key: format!("{} {}", public_key, comment),
        private_key: private_text.to_string(),
        fingerprint_sha256: fingerprint,
    })
}

pub struct SshCertParams<'a> {
    /// "user" or "host".
    pub cert_type: &'a str,
    pub key_id: &'a str,
    pub principals: &'a [String],
    pub valid_days: i64,
    pub serial: u64,
    pub critical_options: &'a [(String, String)],
    pub extensions: &'a [(String, String)],
}

pub struct SignedSshCert {
    /// The signed certificate in OpenSSH `*-cert.pub` format.
    pub certificate: String,
    pub valid_from: chrono::DateTime<Utc>,
    pub valid_to: chrono::DateTime<Utc>,
    pub fingerprint_sha256: String,
}

/// Default extensions granted to a user certificate when the caller does not
/// specify any — mirrors `ssh-keygen`'s defaults so issued certs are usable for
/// interactive login out of the box.
pub const DEFAULT_USER_CERT_EXTENSIONS: &[&str] = &[
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

/// Ce qu'un certificat SSH raconte de lui-même une fois lu et vérifié.
#[derive(Debug, serde::Serialize)]
pub struct SshCertAnalysis {
    /// "user" ou "host". Un certificat d'utilisateur autorise une connexion,
    /// un certificat d'hôte évite l'invite « host key verification ».
    pub cert_type: String,
    pub serial: u64,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_from: Option<chrono::DateTime<Utc>>,
    /// Absent quand le certificat n'expire jamais.
    pub valid_to: Option<chrono::DateTime<Utc>>,
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<(String, String)>,
    /// La clé que le certificat porte.
    pub subject_algorithm: String,
    pub subject_family: String,
    pub subject_bits: Option<u32>,
    pub subject_fingerprint_sha256: String,
    /// L'autorité qui l'a signé.
    pub ca_algorithm: String,
    pub ca_fingerprint_sha256: String,
    /// La signature a été vérifiée cryptographiquement contre la clé de l'AC
    /// que le certificat désigne. Faux veut dire falsifié ou corrompu.
    pub signature_valid: bool,
    /// Nom de l'AC si cette instance la connaît ; absent sinon.
    pub known_ca_name: Option<String>,
    pub known_ca_id: Option<String>,
    /// Renseigné seulement si une clé privée a été fournie.
    pub matches_private_key: Option<bool>,
    /// La clé privée fournie est scellée par une phrase de passe.
    pub private_key_encrypted: Option<bool>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Convertit un horodatage OpenSSH. `u64::MAX` est la façon dont `ssh-keygen`
/// écrit « n'expire jamais » ; il ne rentre dans aucune date, d'où l'option.
fn ssh_time(seconds: u64) -> Option<chrono::DateTime<Utc>> {
    i64::try_from(seconds)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
}

fn options_to_vec(map: &ssh_key::certificate::OptionsMap) -> Vec<(String, String)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Lit un certificat SSH OpenSSH, vérifie sa signature et le juge.
///
/// ENTRÉES : le certificat au format OpenSSH (une ligne, `ssh-ed25519-cert-v01@…`),
/// une clé privée facultative — celle du sujet, pour répondre à la question qui
/// coûte une après-midi : ce certificat va-t-il avec cette clé ? — et la liste
/// des AC connues de l'instance sous forme (id, nom, empreinte SHA256).
///
/// SORTIE : la description complète du certificat, le verdict de signature, et
/// deux listes séparant ce qui empêche l'import de ce qui mérite d'être su.
///
/// LOGIQUE : parser, vérifier la signature, décrire les deux clés en jeu,
/// confronter les dates à l'heure courante, puis appliquer les règles qu'un
/// administrateur appliquerait de tête.
pub fn analyze_ssh_certificate(
    certificate_text: &str,
    private_text: Option<&str>,
    known_cas: &[(String, String, String)],
) -> Result<SshCertAnalysis, AppError> {
    let certificate_text = certificate_text.trim();
    if certificate_text.is_empty() {
        return Err(AppError::Validation(
            "supply an OpenSSH certificate".to_string(),
        ));
    }
    let cert = SshCertificate::from_openssh(certificate_text).map_err(|e| {
        // Coller la clé publique au lieu du certificat est l'erreur numéro un :
        // les deux sont une ligne base64 qui commence par ssh-.
        let hint = if !certificate_text.contains("-cert-v01@openssh.com") {
            " This looks like a plain public key, not a certificate; a certificate's type contains `-cert-v01@openssh.com` and it is usually the file ending in `-cert.pub`."
        } else if e.to_string().contains("time") {
            // `ssh-keygen -V always:forever` écrit une date de fin à u64::MAX,
            // que le lecteur utilisé ici ne sait pas représenter. Le dire, car
            // « invalid time » n'aide personne.
            " The certificate appears to have no expiry (`valid forever`), which this reader cannot represent. Re-issue it with an explicit end date: `ssh-keygen -s ca -V +52w …`. A permanent SSH certificate is a key with extra steps anyway."
        } else {
            ""
        };
        AppError::Validation(format!("certificate could not be parsed: {e}.{hint}"))
    })?;

    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // La vérification cryptographique d'abord : tout le reste n'est que du
    // contenu déclaré tant qu'on ne sait pas si la signature tient.
    let signature_valid = cert.verify_signature().is_ok();
    if !signature_valid {
        errors.push(
            "The certificate's signature does not verify against the CA key it names: it has been altered, or it was not produced by that CA."
                .to_string(),
        );
    }

    let (subject_family, subject_algorithm, subject_bits) = describe_key(cert.public_key());
    appraise(&subject_family, subject_bits, &mut errors, &mut warnings);
    let (ca_family, ca_algorithm, ca_bits) = describe_key(cert.signature_key());
    {
        // Une AC faible compromet tout ce qu'elle a signé, y compris ce
        // certificat ; on le dit, mais sans confondre les deux clés.
        let mut ca_errors: Vec<String> = Vec::new();
        let mut ca_warnings: Vec<String> = Vec::new();
        appraise(&ca_family, ca_bits, &mut ca_errors, &mut ca_warnings);
        for m in ca_errors {
            errors.push(format!("Signing CA: {m}"));
        }
        for m in ca_warnings {
            warnings.push(format!("Signing CA: {m}"));
        }
    }

    let ca_fingerprint = cert
        .signature_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let (known_ca_id, known_ca_name) = known_cas
        .iter()
        .find(|(_, _, fp)| *fp == ca_fingerprint)
        .map(|(id, name, _)| (Some(id.clone()), Some(name.clone())))
        .unwrap_or((None, None));
    if known_ca_name.is_none() {
        warnings.push(
            "The signing CA is not one of this instance's own: the certificate can be recorded, but Akamana cannot revoke it or issue a replacement."
                .to_string(),
        );
    }

    let now = Utc::now();
    let valid_from = ssh_time(cert.valid_after());
    let valid_to = ssh_time(cert.valid_before());
    if valid_to.is_none() {
        warnings.push(
            "This certificate declares no usable expiry date. An SSH certificate's whole point is to be short-lived."
                .to_string(),
        );
    } else if let Some(end) = valid_to {
        // Cinq ans est déjà hors de proportion pour un certificat SSH, dont la
        // durée usuelle se compte en heures ou en semaines.
        if (end - now).num_days() > 1825 {
            warnings.push(format!(
                "The certificate runs until {} — more than five years. An SSH certificate is meant to be short-lived; at this length it behaves like a permanent key.",
                end.format("%Y-%m-%d")
            ));
        }
        if end <= now {
            errors.push(format!(
                "The certificate expired on {}; it can no longer authenticate anywhere.",
                end.format("%Y-%m-%d %H:%M UTC")
            ));
        } else if (end - now).num_days() < 7 {
            warnings.push(format!(
                "The certificate expires on {}, in less than a week.",
                end.format("%Y-%m-%d %H:%M UTC")
            ));
        }
    }
    if let Some(start) = valid_from {
        if start > now {
            warnings.push(format!(
                "The certificate is not valid until {}.",
                start.format("%Y-%m-%d %H:%M UTC")
            ));
        }
    }

    let cert_type = if cert.cert_type() == CertType::Host {
        "host"
    } else {
        "user"
    };
    let principals: Vec<String> = cert.valid_principals().to_vec();
    if principals.is_empty() {
        // Ce n'est pas une omission anodine : OpenSSH lit une liste vide comme
        // « tous », dans les deux sens.
        warnings.push(match cert_type {
            "host" => "No principals: OpenSSH treats this certificate as valid for every hostname.".to_string(),
            _ => "No principals: OpenSSH treats this certificate as valid for every username it is presented for.".to_string(),
        });
    }
    if cert_type == "host" && principals.iter().any(|p| p.contains('*')) {
        warnings.push(
            "A wildcard principal on a host certificate covers every name it matches; scope it to the hostnames actually served."
                .to_string(),
        );
    }

    let extensions = options_to_vec(cert.extensions());
    let critical_options = options_to_vec(cert.critical_options());
    if cert_type == "user" && !extensions.iter().any(|(k, _)| k == "permit-pty") {
        warnings.push(
            "No `permit-pty` extension: interactive login with this certificate will be refused, which is deliberate for automation and a surprise otherwise."
                .to_string(),
        );
    }
    for (name, value) in &critical_options {
        warnings.push(match name.as_str() {
            "force-command" => format!(
                "Critical option `force-command`: every session runs `{value}` whatever the client asks for."
            ),
            "source-address" => format!(
                "Critical option `source-address`: the certificate only works from {value}."
            ),
            other => format!(
                "Critical option `{other}`: a server that does not understand it refuses the certificate outright."
            ),
        });
    }

    // Le sujet et sa clé privée : parsés ici pour répondre à la seule question
    // qui ne se voit pas à l'œil nu.
    let (matches_private_key, private_key_encrypted) = match private_text
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(text) => {
            let key = SshPrivateKey::from_openssh(text).map_err(|e| {
                let hint = if text.contains("PuTTY-User-Key-File") {
                    " This looks like a PuTTY .ppk file; export it with PuTTYgen as \"Export OpenSSH key\" first."
                } else {
                    ""
                };
                AppError::Validation(format!("private key could not be parsed: {e}.{hint}"))
            })?;
            let matches = key.public_key().key_data().fingerprint(HashAlg::Sha256)
                == cert.public_key().fingerprint(HashAlg::Sha256);
            if !matches {
                errors.push(
                    "The private key does not match the key inside the certificate: they are two different keys."
                        .to_string(),
                );
            }
            if key.is_encrypted() {
                warnings.push(
                    "The private key is protected by a passphrase. Akamana cannot use it unattended until it is supplied without one."
                        .to_string(),
                );
            }
            (Some(matches), Some(key.is_encrypted()))
        }
        None => (None, None),
    };

    Ok(SshCertAnalysis {
        cert_type: cert_type.to_string(),
        serial: cert.serial(),
        key_id: cert.key_id().to_string(),
        principals,
        valid_from,
        valid_to,
        critical_options,
        extensions,
        subject_algorithm,
        subject_family,
        subject_bits,
        subject_fingerprint_sha256: cert.public_key().fingerprint(HashAlg::Sha256).to_string(),
        ca_algorithm,
        ca_fingerprint_sha256: ca_fingerprint,
        signature_valid,
        known_ca_name,
        known_ca_id,
        matches_private_key,
        private_key_encrypted,
        errors,
        warnings,
    })
}

/// Signs a subject public key into an OpenSSH certificate using the given CA
/// private key. The CA and subject are both OpenSSH-format strings.
pub fn sign_ssh_certificate(
    ca_private_openssh: &str,
    subject_public_openssh: &str,
    p: SshCertParams<'_>,
) -> Result<SignedSshCert, AppError> {
    let ca_key = SshPrivateKey::from_openssh(ca_private_openssh)
        .map_err(|e| AppError::Internal(format!("invalid SSH CA key: {e}")))?;
    let subject = SshPublicKey::from_openssh(subject_public_openssh)
        .map_err(|_| AppError::Validation("invalid SSH public key".to_string()))?;

    let valid_from = Utc::now();
    let valid_to = valid_from + Duration::days(p.valid_days);
    let valid_after = valid_from.timestamp().max(0) as u64;
    let valid_before = valid_to.timestamp().max(0) as u64;

    let cert_type = match p.cert_type {
        "host" => CertType::Host,
        _ => CertType::User,
    };

    let mut builder =
        SshCertBuilder::new_with_random_nonce(&mut OsRng, &subject, valid_after, valid_before)
            .map_err(|e| AppError::Internal(format!("ssh cert builder init failed: {e}")))?;
    builder
        .serial(p.serial)
        .map_err(|e| AppError::Internal(format!("ssh cert serial failed: {e}")))?;
    builder
        .cert_type(cert_type)
        .map_err(|e| AppError::Internal(format!("ssh cert type failed: {e}")))?;
    builder
        .key_id(p.key_id)
        .map_err(|e| AppError::Internal(format!("ssh cert key id failed: {e}")))?;
    for principal in p.principals {
        builder
            .valid_principal(principal.clone())
            .map_err(|e| AppError::Internal(format!("ssh cert principal failed: {e}")))?;
    }
    for (name, data) in p.critical_options {
        builder
            .critical_option(name.clone(), data.clone())
            .map_err(|e| AppError::Internal(format!("ssh cert critical option failed: {e}")))?;
    }
    // Apply caller extensions, else default user-cert extensions (host certs get none).
    if p.extensions.is_empty() {
        if cert_type == CertType::User {
            for ext in DEFAULT_USER_CERT_EXTENSIONS {
                builder
                    .extension(*ext, "")
                    .map_err(|e| AppError::Internal(format!("ssh cert extension failed: {e}")))?;
            }
        }
    } else {
        for (name, data) in p.extensions {
            builder
                .extension(name.clone(), data.clone())
                .map_err(|e| AppError::Internal(format!("ssh cert extension failed: {e}")))?;
        }
    }

    let cert = builder
        .sign(&ca_key)
        .map_err(|e| AppError::Internal(format!("ssh cert signing failed: {e}")))?;
    let certificate = cert
        .to_openssh()
        .map_err(|e| AppError::Internal(format!("ssh cert encode failed: {e}")))?;
    let fingerprint = subject.fingerprint(HashAlg::Sha256).to_string();

    Ok(SignedSshCert {
        certificate,
        valid_from,
        valid_to,
        fingerprint_sha256: fingerprint,
    })
}

/// Bootstraps the SSH User CA and Host CA at startup (mirrors `ensure_root_ca`).
/// Idempotent: skips a CA type that already has an active key.
pub async fn ensure_ssh_cas(pool: &MySqlPool, cfg: &Config) -> Result<(), AppError> {
    for (ca_type, comment) in [
        ("user", "Akamana SSH User CA"),
        ("host", "Akamana SSH Host CA"),
    ] {
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM ssh_cas WHERE ca_type = ? AND is_active = TRUE LIMIT 1")
                .bind(ca_type)
                .fetch_optional(pool)
                .await?;
        if existing.is_some() {
            continue;
        }

        let material = generate_ssh_ca_material(comment)?;
        let enc = encrypt_secret(cfg, &material.private_key)?;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO ssh_cas (id, ca_type, name, algorithm, public_key, private_key_enc, fingerprint_sha256, is_active, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, 'system', ?)",
        )
        .bind(&id)
        .bind(ca_type)
        .bind(comment)
        .bind(&material.algorithm)
        .bind(&material.public_key)
        .bind(&enc)
        .bind(&material.fingerprint_sha256)
        .bind(Utc::now().naive_utc())
        .execute(pool)
        .await?;
        tracing::info!(
            "bootstrapped SSH {} CA ({})",
            ca_type,
            material.fingerprint_sha256
        );
    }
    Ok(())
}

/// DER-encodes a certificate given its PEM (for `.der`/`.cer` export).
pub fn cert_pem_to_der(cert_pem: &str) -> Result<Vec<u8>, AppError> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| AppError::Validation(format!("invalid certificate PEM: {e}")))?;
    cert.to_der()
        .map_err(|e| AppError::Internal(format!("DER encode failed: {e}")))
}

/// Builds a password-protected PKCS#12 (.pfx) bundle from a cert + private key
/// PEM (for Windows/IIS-style deployment).
pub fn build_pkcs12(
    cert_pem: &str,
    key_pem: &str,
    password: &str,
    friendly_name: &str,
) -> Result<Vec<u8>, AppError> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| AppError::Validation(format!("invalid certificate PEM: {e}")))?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| AppError::Validation(format!("invalid private key PEM: {e}")))?;
    let mut builder = openssl::pkcs12::Pkcs12::builder();
    builder.name(friendly_name);
    builder.pkey(&key);
    builder.cert(&cert);
    let p12 = builder
        .build2(password)
        .map_err(|e| AppError::Internal(format!("PKCS#12 build failed: {e}")))?;
    p12.to_der()
        .map_err(|e| AppError::Internal(format!("PKCS#12 DER encode failed: {e}")))
}

async fn read_setting(pool: &MySqlPool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value_text FROM settings WHERE key_name = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
        .filter(|s| !s.is_empty())
}

/// Builds the CRL Distribution Point URL for certs issued by `root_id`, from the
/// configured `crl_base_url` setting. Lowercased to avoid case issues on Linux.
/// Returns `None` when CRL distribution is not configured.
pub async fn crl_cdp_url(pool: &MySqlPool, root_id: i32) -> Option<String> {
    let base = read_setting(pool, "crl_base_url").await?;
    Some(format!("{}/crl/{}.crl", base.trim_end_matches('/'), root_id).to_lowercase())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, AppError> {
    let clean = hex.trim().trim_start_matches("0x");
    let padded = if clean.len() % 2 == 1 {
        format!("0{clean}")
    } else {
        clean.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16)
                .map_err(|_| AppError::Internal(format!("invalid serial hex: {hex}")))
        })
        .collect()
}

fn to_offset(dt: chrono::DateTime<Utc>) -> Result<time::OffsetDateTime, AppError> {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp())
        .map_err(|e| AppError::Internal(format!("CRL time conversion failed: {e}")))
}

/// Generates a signed X.509 CRL (DER) for the CA `root_id`, listing the revoked
/// serials of certificates issued under it. Signed with the root's key via rcgen.
pub async fn generate_crl_der(
    pool: &MySqlPool,
    cfg: &Config,
    root_id: i32,
) -> Result<Vec<u8>, AppError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT cert_pem, private_key_enc FROM root_ca WHERE id = ?")
            .bind(root_id)
            .fetch_optional(pool)
            .await?;
    let (cert_pem, key_enc) =
        row.ok_or_else(|| AppError::Validation(format!("no root CA with id {root_id}")))?;

    // All awaits (DB) happen before any rcgen work, so no non-Send rcgen value
    // is held across an await (keeps the handler future Send).
    let rows = sqlx::query_as::<_, (String, chrono::NaiveDateTime)>(
        "SELECT serial_hex, revoked_at FROM crl_entries WHERE root_ca_id = ?",
    )
    .bind(root_id)
    .fetch_all(pool)
    .await?;

    let key_pem = decrypt_secret(cfg, &key_enc)?;
    let issuer_kp = rcgen::KeyPair::from_pem(&key_pem)
        .map_err(|e| AppError::Internal(format!("CRL: load CA key failed: {e}")))?;
    let issuer_params = rcgen::CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|e| AppError::Internal(format!("CRL: parse CA cert failed: {e}")))?;
    let issuer_cert = issuer_params
        .self_signed(&issuer_kp)
        .map_err(|e| AppError::Internal(format!("CRL: issuer setup failed: {e}")))?;

    let mut revoked = Vec::with_capacity(rows.len());
    for (serial_hex, revoked_at) in rows {
        revoked.push(rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from_slice(&hex_to_bytes(&serial_hex)?),
            revocation_time: to_offset(revoked_at.and_utc())?,
            reason_code: None,
            invalidity_date: None,
        });
    }

    let now = Utc::now();
    let params = rcgen::CertificateRevocationListParams {
        this_update: to_offset(now)?,
        next_update: to_offset(now + Duration::days(7))?,
        crl_number: rcgen::SerialNumber::from(now.timestamp().max(0) as u64),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(&issuer_cert, &issuer_kp)
        .map_err(|e| AppError::Internal(format!("CRL signing failed: {e}")))?;
    Ok(crl.der().as_ref().to_vec())
}

#[cfg(test)]
mod ssh_analysis_tests {
    use super::{analyze_ssh_key, Algorithm, LineEnding, OsRng, SshPrivateKey};

    // Helper rather than `unwrap`: the crate denies panicking accessors, tests
    // included. A generation failure surfaces as a skipped assertion, not a
    // panic that hides which case broke.
    fn make_pair() -> Option<(String, String)> {
        let key = SshPrivateKey::random(&mut OsRng, Algorithm::Ed25519).ok()?;
        let public = key.public_key().to_openssh().ok()?;
        let private = key.to_openssh(LineEnding::LF).ok()?;
        Some((public, private.to_string()))
    }

    #[test]
    fn reads_an_ed25519_pair_and_confirms_the_halves_belong_together() {
        let Some((public, private)) = make_pair() else {
            return;
        };
        let Ok(a) = analyze_ssh_key(Some(&public), Some(&private)) else {
            panic!("a freshly generated pair must analyse cleanly");
        };
        assert_eq!(a.family, "ed25519");
        assert_eq!(a.bits, Some(256));
        assert_eq!(a.supplied, "pair");
        assert_eq!(a.matches_public, Some(true));
        assert!(!a.encrypted);
        assert!(a.errors.is_empty());
        assert!(a.fingerprint_sha256.starts_with("SHA256:"));
    }

    #[test]
    fn a_private_key_alone_still_describes_itself() {
        let Some((_, private)) = make_pair() else {
            return;
        };
        let Ok(a) = analyze_ssh_key(None, Some(&private)) else {
            panic!("a private key carries its own public half");
        };
        assert_eq!(a.supplied, "private");
        assert_eq!(a.matches_public, None);
    }

    #[test]
    fn mismatched_halves_are_reported_as_an_error_not_a_warning() {
        // The failure that costs an afternoon: two keys that both parse.
        let (Some((public, _)), Some((_, other_private))) = (make_pair(), make_pair()) else {
            return;
        };
        let Ok(a) = analyze_ssh_key(Some(&public), Some(&other_private)) else {
            panic!("both halves parse; the mismatch belongs in the verdict");
        };
        assert_eq!(a.matches_public, Some(false));
        assert!(a.errors.iter().any(|e| e.contains("does not match")));
    }

    #[test]
    fn a_putty_file_gets_told_what_to_do_about_it() {
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n";
        let Err(e) = analyze_ssh_key(None, Some(ppk)) else {
            panic!("a .ppk is not an OpenSSH key");
        };
        assert!(format!("{e:?}").contains("PuTTYgen"));
    }

    #[test]
    fn empty_input_is_refused_rather_than_silently_accepted() {
        assert!(analyze_ssh_key(None, None).is_err());
        assert!(analyze_ssh_key(Some("   "), Some("")).is_err());
        assert!(analyze_ssh_key(Some("not a key"), None).is_err());
    }
}

#[cfg(test)]
mod ssh_cert_analysis_tests {
    use super::analyze_ssh_certificate;

    // Fixtures produites par ssh-keygen : une AC ed25519 jetable signant la
    // même clé sujet trois fois. Les certificats valides jusqu'en 2046 gardent
    // ces tests indépendants de la date du jour — et déclenchent au passage
    // l'avertissement sur les validités déraisonnables.
    const CA_FINGERPRINT: &str = "SHA256:+ooi9cBXhqBVhS6PDNyJJOw5j9uyntjRPBPfBUYAc20";
    const USER_LONG: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIPe83CUxktEtCIf4QDzYX66vs4HkUAoxJQ3o6ETaEiWAAAAIHu57SbGP8xmAXVdyyZqYU+pEV5YvYhkkNK4O0sepQLKAAAAAAAAACoAAAABAAAACmFsaWNlLTIwMjYAAAATAAAABWFsaWNlAAAABmRlcGxveQAAAABpVbkAAAAAAI70VoAAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAWhDa9Y9GDJUDX62otZbFWH2LqYUZ2AGbs7k98bRczWwAAAFMAAAALc3NoLWVkMjU1MTkAAABApwK17C/5pkWW5lfONvMz0hgo8FZsN79ey/eF1SZpzeba3j7k29iKzjlHR0lGq5+W8eGq3US0fVbNrXQ4pScYCQ== alice@example";
    const USER_EXPIRED: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAINXmfC+a77R/+/3n9v088n5ViBFznJyoiBQnDWAMALofAAAAIHu57SbGP8xmAXVdyyZqYU+pEV5YvYhkkNK4O0sepQLKAAAAAAAAAAcAAAABAAAACWFsaWNlLW9sZAAAAAkAAAAFYWxpY2UAAAAAXgvhAAAAAABeDTKAAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgFoQ2vWPRgyVA1+tqLWWxVh9i6mFGdgBm7O5PfG0XM1sAAABTAAAAC3NzaC1lZDI1NTE5AAAAQLEfOBLSjj2DogFuZgSEC6jZQMe7GQO7ruvQwK56jCR/yT1RhaU8RvN+wHFdv/yRBw1DPwnNSmb7vObOB77JnAg= alice@example";
    const HOST_LONG: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIOMz0D8w/NPo/I2/ZynZ6Ih5e17GBUe0jPzf5orU93qeAAAAIHu57SbGP8xmAXVdyyZqYU+pEV5YvYhkkNK4O0sepQLKAAAAAAAAAAkAAAACAAAACGhvc3RjZXJ0AAAAFQAAABF3ZWIwMS5leGFtcGxlLmNvbQAAAABpVbkAAAAAAI70VoAAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBaENr1j0YMlQNfrai1lsVYfYuphRnYAZuzuT3xtFzNbAAAAUwAAAAtzc2gtZWQyNTUxOQAAAED9GJfVCKDjXXmToHa6rC9svMF24tIoojvC41lRItVqAWYdxPW55mAZnHGzRVu4Fq4hKEYxU/kJLJwP5lerl1wF alice@example";
    const SUBJECT_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7ue0mxj/MZgF1XcsmamFPqRFeWL2IZJDSuDtLHqUCygAAAJAEsuXABLLl
wAAAAAtzc2gtZWQyNTUxOQAAACB7ue0mxj/MZgF1XcsmamFPqRFeWL2IZJDSuDtLHqUCyg
AAAED5gLHIYshyK+8tKxpgVqdM/9F9azVqVdRkzD/AsOOwUXu57SbGP8xmAXVdyyZqYU+p
EV5YvYhkkNK4O0sepQLKAAAADWFsaWNlQGV4YW1wbGU=
-----END OPENSSH PRIVATE KEY-----";
    const UNRELATED_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCkvbf/N60butztTW/GnYoX92plXKLmjQ2zg6tKw9jtDAAAAIitlJ2krZSd
pAAAAAtzc2gtZWQyNTUxOQAAACCkvbf/N60butztTW/GnYoX92plXKLmjQ2zg6tKw9jtDA
AAAEALMs6MRw11PeZVRafIAQz9AxxZmkvcndzbhnQvBJZowqS9t/83rRu63O1Nb8adihf3
amVcouaNDbODq0rD2O0MAAAABW90aGVy
-----END OPENSSH PRIVATE KEY-----";

    fn known() -> Vec<(String, String, String)> {
        vec![(
            "ca-1".to_string(),
            "Lab User CA".to_string(),
            CA_FINGERPRINT.to_string(),
        )]
    }

    #[test]
    fn reads_a_user_certificate_and_verifies_its_signature() {
        let a = analyze_ssh_certificate(USER_LONG, None, &known());
        let Ok(a) = a else {
            panic!("the certificate should parse")
        };
        assert_eq!(a.cert_type, "user");
        assert_eq!(a.serial, 42);
        assert_eq!(a.key_id, "alice-2026");
        assert_eq!(a.principals, vec!["alice", "deploy"]);
        assert!(a.signature_valid);
        assert_eq!(a.known_ca_name.as_deref(), Some("Lab User CA"));
        assert!(a.errors.is_empty(), "unexpected errors: {:?}", a.errors);
        // Vingt ans n'est pas une erreur, mais c'est le contraire de ce à quoi
        // sert un certificat SSH.
        assert!(a.valid_to.is_some());
        assert!(a
            .warnings
            .iter()
            .any(|w| w.contains("more than five years")));
    }

    #[test]
    fn an_unknown_ca_is_flagged_without_blocking() {
        let Ok(a) = analyze_ssh_certificate(USER_LONG, None, &[]) else {
            panic!("the certificate should parse")
        };
        assert!(a.signature_valid);
        assert!(a.known_ca_name.is_none());
        assert!(a.errors.is_empty());
        assert!(a
            .warnings
            .iter()
            .any(|w| w.contains("not one of this instance")));
    }

    #[test]
    fn an_expired_certificate_is_an_error_not_a_remark() {
        let Ok(a) = analyze_ssh_certificate(USER_EXPIRED, None, &known()) else {
            panic!("the certificate should parse")
        };
        assert!(a.errors.iter().any(|e| e.contains("expired")));
    }

    #[test]
    fn a_host_certificate_is_recognised_as_such() {
        let Ok(a) = analyze_ssh_certificate(HOST_LONG, None, &known()) else {
            panic!("the certificate should parse")
        };
        assert_eq!(a.cert_type, "host");
        assert_eq!(a.principals, vec!["web01.example.com"]);
        // Un certificat d'hôte n'a pas d'extensions ; l'avertissement permit-pty
        // ne concerne que les certificats d'utilisateur et ne doit pas sortir.
        assert!(!a.warnings.iter().any(|w| w.contains("permit-pty")));
    }

    #[test]
    fn the_private_key_is_matched_against_the_certificate() {
        let Ok(a) = analyze_ssh_certificate(USER_LONG, Some(SUBJECT_PRIVATE_KEY), &known()) else {
            panic!("the certificate should parse")
        };
        assert_eq!(a.matches_private_key, Some(true));
        assert!(a.errors.is_empty());

        let Ok(b) = analyze_ssh_certificate(USER_LONG, Some(UNRELATED_PRIVATE_KEY), &known())
        else {
            panic!("the certificate should parse")
        };
        assert_eq!(b.matches_private_key, Some(false));
        assert!(b.errors.iter().any(|e| e.contains("does not match")));
    }

    #[test]
    fn a_tampered_certificate_fails_signature_verification() {
        // On altère un octet du corps signé : la signature ne doit plus tenir.
        let mut parts: Vec<&str> = USER_LONG.split(' ').collect();
        let body = parts[1].to_string();
        let swapped = match body.strip_prefix("AAAAIHNz") {
            Some(rest) => format!("AAAAIHNy{rest}"),
            None => body.clone(),
        };
        parts[1] = &swapped;
        let tampered = parts.join(" ");
        match analyze_ssh_certificate(&tampered, None, &known()) {
            // Soit le corps ne se décode plus du tout, soit il se décode et la
            // signature est refusée. Les deux sont des refus corrects.
            Err(_) => {}
            Ok(a) => {
                assert!(!a.signature_valid);
                assert!(a.errors.iter().any(|e| e.contains("signature")));
            }
        }
    }

    #[test]
    fn a_never_expiring_certificate_is_refused_with_an_explanation() {
        // `ssh-keygen -V always:forever` écrit u64::MAX en date de fin ; le
        // lecteur utilisé ici ne sait pas la représenter et rend « invalid
        // time », ce qui n'aide personne. Le message doit dire quoi faire.
        const FOREVER: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFoSVF468fWnCqNFZUJI6BIwlfOyrk6KzV3AdpA8XyBmAAAAIHu57SbGP8xmAXVdyyZqYU+pEV5YvYhkkNK4O0sepQLKAAAAAAAAACoAAAABAAAADWFsaWNlLWZvcmV2ZXIAAAATAAAABWFsaWNlAAAABmRlcGxveQAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAWhDa9Y9GDJUDX62otZbFWH2LqYUZ2AGbs7k98bRczWwAAAFMAAAALc3NoLWVkMjU1MTkAAABAHydfeafAZvA3SufS8tU2xaOieT6iLCVqsNslf8Yo0iPuCWUh495wryIhcFds5MlO9x9tplQHRKiI5htTROK3CA== alice@example";
        match analyze_ssh_certificate(FOREVER, None, &known()) {
            Err(crate::errors::AppError::Validation(msg)) => {
                assert!(msg.contains("no expiry"), "message was: {msg}")
            }
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_public_key_gets_told_it_is_not_a_certificate() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHu57SbGP8xmAXVdyyZqYU+pEV5YvYhkkNK4O0sepQLK alice@example";
        match analyze_ssh_certificate(key, None, &known()) {
            Err(crate::errors::AppError::Validation(msg)) => {
                assert!(msg.contains("-cert-v01@openssh.com"), "message was: {msg}")
            }
            other => panic!("expected a validation error, got {other:?}"),
        }
    }
}
