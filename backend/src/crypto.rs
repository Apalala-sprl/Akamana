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
        X509Builder, X509Name, X509NameBuilder, X509,
    },
};
use rand::RngCore;
use rand_core::OsRng;
use sqlx::MySqlPool;
use ssh_key::{
    certificate::{Builder as SshCertBuilder, CertType},
    private::PrivateKey as SshPrivateKey,
    public::PublicKey as SshPublicKey,
    Algorithm, HashAlg, LineEnding,
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

/// SHA-256 (hex) of an API token, for constant-shape storage/lookup. Uses the
/// already-vendored OpenSSL rather than pulling in a separate `sha2` crate.
pub fn hash_api_token(token: &str) -> String {
    let digest = openssl::sha::sha256(token.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
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

pub async fn ensure_root_ca(pool: &MySqlPool, cfg: &Config) -> Result<(), AppError> {
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM root_ca WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    if exists.is_some() {
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
/// CA public key (e.g. "CryptoKeyMancer SSH User CA").
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
        ("user", "CryptoKeyMancer SSH User CA"),
        ("host", "CryptoKeyMancer SSH Host CA"),
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
