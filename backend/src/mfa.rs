//! Second-factor primitives: RFC 4648 base32, RFC 6238 TOTP (HMAC-SHA1,
//! 6 digits, 30 s step) and one-time recovery codes.
//!
//! TOTP is implemented here rather than pulled in as a dependency: the whole
//! algorithm is a few dozen lines on top of the already-vendored OpenSSL HMAC,
//! which is the same reasoning behind `crypto::hash_api_token` not using `sha2`.

use crate::errors::{AppError, AppResult};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use rand::RngCore;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Alphabet for recovery codes. Excludes the characters people mistype when
/// reading a code off a printout (0/O, 1/I/L, U/V).
const RECOVERY_ALPHABET: &[u8; 25] = b"ABCDEFGHJKMNPQRSTWXYZ2345";

pub const TOTP_STEP_SECONDS: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;

/// Number of 30 s steps accepted either side of the current one, to absorb
/// clock drift between the server and the authenticator app.
const TOTP_SKEW_STEPS: i64 = 1;

/// Number of recovery codes minted per enrollment.
pub const RECOVERY_CODE_COUNT: usize = 10;

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 0x1f) as usize;
            out.push(char::from(BASE32_ALPHABET[idx]));
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 0x1f) as usize;
        out.push(char::from(BASE32_ALPHABET[idx]));
    }
    out
}

/// Decodes base32, tolerating the separators authenticator apps let users type
/// (spaces, dashes) and `=` padding. Returns `None` on any other character.
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for ch in input.chars() {
        if ch == '=' || ch == ' ' || ch == '-' {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let idx = BASE32_ALPHABET.iter().position(|&c| c == upper)? as u32;
        bits = (bits << 5) | idx;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// A fresh 160-bit TOTP secret, base32-encoded (the format every authenticator
/// app accepts for manual entry).
pub fn generate_totp_secret() -> String {
    let mut bytes = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> AppResult<Vec<u8>> {
    let pkey =
        PKey::hmac(key).map_err(|e| AppError::Internal(format!("HMAC key setup failed: {e}")))?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)
        .map_err(|e| AppError::Internal(format!("HMAC init failed: {e}")))?;
    signer
        .update(msg)
        .map_err(|e| AppError::Internal(format!("HMAC update failed: {e}")))?;
    signer
        .sign_to_vec()
        .map_err(|e| AppError::Internal(format!("HMAC finalize failed: {e}")))
}

/// RFC 4226 HOTP over an arbitrary counter.
fn hotp(secret: &[u8], counter: u64) -> AppResult<String> {
    let mac = hmac_sha1(secret, &counter.to_be_bytes())?;
    let offset = usize::from(mac.last().copied().unwrap_or(0) & 0x0f);
    let slice = mac
        .get(offset..offset + 4)
        .ok_or_else(|| AppError::Internal("HMAC output too short for HOTP".to_string()))?;
    let binary = ((u32::from(slice[0]) & 0x7f) << 24)
        | (u32::from(slice[1]) << 16)
        | (u32::from(slice[2]) << 8)
        | u32::from(slice[3]);
    let modulo = 10_u32.pow(TOTP_DIGITS);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = TOTP_DIGITS as usize
    ))
}

/// The TOTP code for `secret_b32` at a given unix timestamp.
pub fn totp_code_at(secret_b32: &str, unix_time: u64) -> AppResult<String> {
    let secret = base32_decode(secret_b32)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Internal("TOTP secret is not valid base32".to_string()))?;
    hotp(&secret, unix_time / TOTP_STEP_SECONDS)
}

/// Constant-time check of a user-supplied code against the current time step
/// and one step either side. Returns false for anything malformed rather than
/// erroring, so callers can treat it as a plain "wrong code".
///
/// Every candidate step is evaluated even after a match, so the time taken
/// doesn't leak which step matched.
pub fn verify_totp(secret_b32: &str, code: &str, unix_time: u64) -> bool {
    let cleaned: String = code.chars().filter(char::is_ascii_digit).collect();
    if cleaned.len() != TOTP_DIGITS as usize {
        return false;
    }

    let mut matched = false;
    for delta in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
        let Some(shifted) = unix_time.checked_add_signed(delta * TOTP_STEP_SECONDS as i64) else {
            continue;
        };
        let Ok(candidate) = totp_code_at(secret_b32, shifted) else {
            continue;
        };
        // Both sides are exactly TOTP_DIGITS ASCII digits, so the lengths match
        // and `memcmp::eq` is safe to call.
        if openssl::memcmp::eq(candidate.as_bytes(), cleaned.as_bytes()) {
            matched = true;
        }
    }
    matched
}

/// The `otpauth://` URI an authenticator app scans or imports.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let issuer_enc = percent_encode(issuer);
    let account_enc = percent_encode(account);
    format!(
        "otpauth://totp/{issuer_enc}:{account_enc}?secret={secret_b32}&issuer={issuer_enc}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )
}

/// Minimal RFC 3986 percent-encoding for the label/issuer path components of
/// an otpauth URI.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Fresh recovery codes in `XXXXX-XXXXX` form. Returned to the operator once;
/// only SHA-256 hashes of the normalized form are stored.
pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut raw = [0_u8; 10];
        rng.fill_bytes(&mut raw);
        let chars: String = raw
            .iter()
            .map(|b| char::from(RECOVERY_ALPHABET[usize::from(*b) % RECOVERY_ALPHABET.len()]))
            .collect();
        codes.push(format!("{}-{}", &chars[..5], &chars[5..]));
    }
    codes
}

/// Recovery codes are compared case- and separator-insensitively, so a user can
/// type `abcde fghij` for `ABCDE-FGHIJ`.
pub fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips() {
        let data = b"12345678901234567890";
        let encoded = base32_encode(data);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&encoded).as_deref(), Some(&data[..]));
    }

    #[test]
    fn totp_matches_rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, SHA-1 seed "12345678901234567890" truncated to
        // 6 digits (the RFC prints 8; we take the low 6).
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(totp_code_at(&secret, 59).ok().as_deref(), Some("287082"));
        assert_eq!(
            totp_code_at(&secret, 1111111109).ok().as_deref(),
            Some("081804")
        );
        assert_eq!(
            totp_code_at(&secret, 1234567890).ok().as_deref(),
            Some("005924")
        );
    }

    #[test]
    fn verify_accepts_adjacent_steps_and_rejects_junk() {
        let secret = base32_encode(b"12345678901234567890");
        // 59 and 89 are adjacent 30 s steps.
        assert!(verify_totp(&secret, "287082", 89));
        assert!(!verify_totp(&secret, "287082", 1234567890));
        assert!(!verify_totp(&secret, "abc", 59));
        assert!(!verify_totp(&secret, "", 59));
    }

    #[test]
    fn recovery_codes_normalize() {
        assert_eq!(normalize_recovery_code("abcde-fghij"), "ABCDEFGHIJ");
        assert_eq!(normalize_recovery_code("ABCDE FGHIJ"), "ABCDEFGHIJ");
        let codes = generate_recovery_codes(RECOVERY_CODE_COUNT);
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert!(codes.iter().all(|c| c.len() == 11 && c.contains('-')));
    }
}
