//! Encrypted backup container format (`.ezbak`).
//!
//! Layout: `EZBAK1\n` magic, then a one-line JSON header, then `\n`, then the
//! binary ciphertext. The plaintext is gzip-compressed, then encrypted with
//! AES-256-GCM. Two key modes are supported:
//!  - **passphrase**: the 256-bit key is derived from a backup passphrase with
//!    Argon2id (parameters + salt recorded in the header).
//!  - **envelope** (added in a later phase): a random data key (DEK) encrypts
//!    the backup and is wrapped for one or more recipient public keys.
//!
//! The format is intentionally self-describing so a backup can be restored on a
//! different instance given the passphrase (or a recipient private key).

use crate::errors::AppError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use openssl::rsa::{Padding, Rsa};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const MAGIC: &[u8] = b"EZBAK1\n";

/// Argon2id parameters recorded so a backup is decryptable independently of the
/// current build defaults. Values are the argon2 crate's OWASP-ish defaults.
const ARGON_M_COST: u32 = 19456;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algo: String,
    salt: String,
    m: u32,
    t: u32,
    p: u32,
}

/// One recipient's copy of the data key (DEK), wrapped to their public key.
#[derive(Serialize, Deserialize)]
struct RecipientWrap {
    kind: String,
    fp: String,
    wrap: String,
}

#[derive(Serialize, Deserialize)]
struct BackupHeader {
    v: u8,
    mode: String,
    comp: String,
    cipher: String,
    nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipients: Option<Vec<RecipientWrap>>,
    created_at: String,
}

/// A public-key recipient the DEK is wrapped for (envelope mode).
pub struct Recipient {
    pub fingerprint: String,
    pub public_key_pem: String,
}

/// How to encrypt a backup.
pub enum EncMode<'a> {
    Passphrase(&'a str),
    Envelope(&'a [Recipient]),
}

/// How to decrypt a backup.
pub enum Unlock<'a> {
    Passphrase(&'a str),
    PrivateKey {
        pem: &'a str,
        passphrase: Option<&'a str>,
    },
}

/// Loads an RSA public key from SPKI or PKCS#1 PEM.
fn load_rsa_public(pem: &str) -> Result<Rsa<openssl::pkey::Public>, AppError> {
    Rsa::public_key_from_pem(pem.as_bytes())
        .or_else(|_| Rsa::public_key_from_pem_pkcs1(pem.as_bytes()))
        .map_err(|e| AppError::Validation(format!("invalid RSA public key: {e}")))
}

/// SHA-256 (hex) of the DER SubjectPublicKeyInfo — stable across public and
/// private PEM of the same key, so a recipient can be matched at restore time.
fn rsa_fingerprint_from_der(der: &[u8]) -> String {
    let digest = openssl::sha::sha256(der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Validates a recipient public key and returns `(fingerprint, normalized_spki_pem, "rsa")`.
pub fn recipient_from_public_pem(pem: &str) -> Result<(String, String, String), AppError> {
    let rsa = load_rsa_public(pem)?;
    let der = rsa
        .public_key_to_der()
        .map_err(|e| AppError::Internal(format!("public key DER failed: {e}")))?;
    let spki_pem = rsa
        .public_key_to_pem()
        .map_err(|e| AppError::Internal(format!("public key PEM failed: {e}")))?;
    let normalized = String::from_utf8(spki_pem)
        .map_err(|e| AppError::Internal(format!("public key PEM utf8: {e}")))?;
    Ok((
        rsa_fingerprint_from_der(&der),
        normalized,
        "rsa".to_string(),
    ))
}

/// True if `data` looks like an `.ezbak` encrypted container.
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

fn gzip(data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .map_err(|e| AppError::Internal(format!("gzip failed: {e}")))?;
    enc.finish()
        .map_err(|e| AppError::Internal(format!("gzip finish failed: {e}")))
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut dec = GzDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| AppError::Validation(format!("gunzip failed (corrupt backup?): {e}")))?;
    Ok(out)
}

fn derive_passphrase_key(
    pass: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<[u8; 32], AppError> {
    let params = Params::new(m, t, p, Some(32))
        .map_err(|e| AppError::Internal(format!("argon2 params invalid: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| AppError::Internal(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn assemble(header: &BackupHeader, ciphertext: &[u8]) -> Result<Vec<u8>, AppError> {
    let header_json = serde_json::to_string(header)
        .map_err(|e| AppError::Internal(format!("header serialize failed: {e}")))?;
    let mut out = Vec::with_capacity(MAGIC.len() + header_json.len() + 1 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(header_json.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(ciphertext);
    Ok(out)
}

fn parse_container(container: &[u8]) -> Result<(BackupHeader, &[u8]), AppError> {
    let rest = container
        .strip_prefix(MAGIC)
        .ok_or_else(|| AppError::Validation("not an Akamana encrypted backup".to_string()))?;
    let nl = rest
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| AppError::Validation("malformed backup header".to_string()))?;
    let header: BackupHeader = serde_json::from_slice(&rest[..nl])
        .map_err(|e| AppError::Validation(format!("invalid backup header: {e}")))?;
    Ok((header, &rest[nl + 1..]))
}

/// Compresses and encrypts `plaintext` into an `.ezbak` container.
pub fn encrypt_backup(
    plaintext: &[u8],
    mode: EncMode<'_>,
    created_at: &str,
) -> Result<Vec<u8>, AppError> {
    let compressed = gzip(plaintext)?;
    let mut nonce_bytes = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Both modes produce a 32-byte AES key: derived from the passphrase, or a
    // random DEK wrapped for each recipient.
    let (mode_str, key, kdf, recipients): (
        String,
        [u8; 32],
        Option<KdfParams>,
        Option<Vec<RecipientWrap>>,
    ) = match mode {
        EncMode::Passphrase(pass) => {
            if pass.is_empty() {
                return Err(AppError::Validation(
                    "backup passphrase is not set".to_string(),
                ));
            }
            let mut salt = [0_u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = derive_passphrase_key(pass, &salt, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
            (
                "passphrase".to_string(),
                key,
                Some(KdfParams {
                    algo: "argon2id".to_string(),
                    salt: STANDARD.encode(salt),
                    m: ARGON_M_COST,
                    t: ARGON_T_COST,
                    p: ARGON_P_COST,
                }),
                None,
            )
        }
        EncMode::Envelope(recips) => {
            if recips.is_empty() {
                return Err(AppError::Validation(
                    "no backup recipients configured for envelope encryption".to_string(),
                ));
            }
            let mut dek = [0_u8; 32];
            rand::thread_rng().fill_bytes(&mut dek);
            let mut wraps = Vec::with_capacity(recips.len());
            for r in recips {
                let rsa = load_rsa_public(&r.public_key_pem)?;
                let mut out = vec![0_u8; rsa.size() as usize];
                let n = rsa
                    .public_encrypt(&dek, &mut out, Padding::PKCS1_OAEP)
                    .map_err(|e| AppError::Internal(format!("DEK wrap failed: {e}")))?;
                out.truncate(n);
                wraps.push(RecipientWrap {
                    kind: "rsa-oaep".to_string(),
                    fp: r.fingerprint.clone(),
                    wrap: STANDARD.encode(&out),
                });
            }
            ("envelope".to_string(), dek, None, Some(wraps))
        }
    };

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("invalid backup key".to_string()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), compressed.as_ref())
        .map_err(|_| AppError::Internal("backup encryption failed".to_string()))?;

    let header = BackupHeader {
        v: 1,
        mode: mode_str,
        comp: "gzip".to_string(),
        cipher: "aes-256-gcm".to_string(),
        nonce: STANDARD.encode(nonce_bytes),
        kdf,
        recipients,
        created_at: created_at.to_string(),
    };
    assemble(&header, &ciphertext)
}

/// Decrypts and decompresses an `.ezbak` container back to the raw SQL dump.
pub fn decrypt_backup(container: &[u8], unlock: Unlock<'_>) -> Result<Vec<u8>, AppError> {
    let (header, ciphertext) = parse_container(container)?;
    let key: [u8; 32] = match (header.mode.as_str(), unlock) {
        ("passphrase", Unlock::Passphrase(pass)) => {
            let kdf = header
                .kdf
                .ok_or_else(|| AppError::Validation("backup missing KDF parameters".to_string()))?;
            let salt = STANDARD
                .decode(&kdf.salt)
                .map_err(|_| AppError::Validation("invalid backup salt".to_string()))?;
            derive_passphrase_key(pass, &salt, kdf.m, kdf.t, kdf.p)?
        }
        ("envelope", Unlock::PrivateKey { pem, passphrase }) => {
            let rsa_priv = match passphrase {
                Some(pw) if !pw.is_empty() => {
                    Rsa::private_key_from_pem_passphrase(pem.as_bytes(), pw.as_bytes())
                }
                _ => Rsa::private_key_from_pem(pem.as_bytes()),
            }
            .map_err(|e| AppError::Validation(format!("invalid private key: {e}")))?;
            let der = rsa_priv
                .public_key_to_der()
                .map_err(|e| AppError::Internal(format!("public key DER failed: {e}")))?;
            let fp = rsa_fingerprint_from_der(&der);
            let recips = header.recipients.ok_or_else(|| {
                AppError::Validation("backup has no recipient information".to_string())
            })?;
            let wrap = recips.iter().find(|w| w.fp == fp).ok_or_else(|| {
                AppError::Validation("this key is not a recipient of the backup".to_string())
            })?;
            let wrapped = STANDARD
                .decode(&wrap.wrap)
                .map_err(|_| AppError::Validation("invalid wrapped key".to_string()))?;
            let mut out = vec![0_u8; rsa_priv.size() as usize];
            let n = rsa_priv
                .private_decrypt(&wrapped, &mut out, Padding::PKCS1_OAEP)
                .map_err(|_| AppError::Validation("failed to unwrap backup key".to_string()))?;
            out.truncate(n);
            if out.len() != 32 {
                return Err(AppError::Validation(
                    "unwrapped backup key has an unexpected length".to_string(),
                ));
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&out);
            key
        }
        (mode, _) => {
            return Err(AppError::Validation(format!(
                "unsupported backup mode '{mode}' or wrong unlock method"
            )))
        }
    };

    let nonce = STANDARD
        .decode(&header.nonce)
        .map_err(|_| AppError::Validation("invalid backup nonce".to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AppError::Internal("invalid backup key".to_string()))?;
    let compressed = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| AppError::Validation("wrong passphrase or corrupt backup".to_string()))?;
    gunzip(&compressed)
}
