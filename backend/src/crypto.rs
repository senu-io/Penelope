use crate::config::KeyRing;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 0x01;
const VERSION_LEN: usize = 1;
const KEY_ID_LEN: usize = 2;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_ENVELOPE_LEN: usize = VERSION_LEN + KEY_ID_LEN + NONCE_LEN + TAG_LEN; // 31 bytes for empty plaintext

const API_KEY_PREFIX: &str = "pen_live_";
const API_KEY_RANDOM_HEX_LEN: usize = 64;
const API_KEY_TOTAL_LEN: usize = API_KEY_PREFIX.len() + API_KEY_RANDOM_HEX_LEN; // 73 chars

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password hashing failed: {0}")]
    PasswordHashFailed(String),

    #[error("password verification failed: {0}")]
    PasswordVerifyFailed(String),

    #[error("envelope too short: expected at least {MIN_ENVELOPE_LEN} bytes, got {0}")]
    EnvelopeTooShort(usize),

    #[error("unsupported envelope version: {0} (expected {ENVELOPE_VERSION})")]
    UnsupportedVersion(u8),

    #[error("encryption key id {0} not found in keyring")]
    KeyNotFound(u16),

    #[error("decryption failed (ciphertext corrupted, tampered, or aad mismatched)")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("invalid api key format (must start with pen_live_ followed by 64 lowercase hex characters)")]
    InvalidApiKeyFormat,

    #[error("invalid session token format (expected 64 lowercase hex characters)")]
    InvalidSessionTokenFormat,

    #[error("invalid session secret (expected 64 non-zero hex characters)")]
    InvalidSessionSecret,
}

fn argon2_instance() -> Argon2<'static> {
    // parameters aligned with OWASP / SEC-AUTH-01 (19 MiB, 2 iterations, parallelism 1)
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2id parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn is_lowercase_hex(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn build_authenticated_aad(version: u8, key_id: u16, aad: &[u8]) -> Vec<u8> {
    let mut full_aad = Vec::with_capacity(VERSION_LEN + KEY_ID_LEN + aad.len());
    full_aad.push(version);
    full_aad.extend_from_slice(&key_id.to_be_bytes());
    full_aad.extend_from_slice(aad);
    full_aad
}

pub fn hash_password(password: &SecretString) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = argon2_instance();
    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|e| CryptoError::PasswordHashFailed(e.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &SecretString, hash_str: &str) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|e| CryptoError::PasswordVerifyFailed(e.to_string()))?;
    let argon2 = argon2_instance();
    match argon2.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(CryptoError::PasswordVerifyFailed(e.to_string())),
    }
}

// envelope layout: [0x01 | key_id (2B BE) | nonce (12B) | ciphertext + tag]
pub fn encrypt_field(
    keyring: &KeyRing,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (key_id, raw_key) = keyring.active_key();

    let key = Key::<Aes256Gcm>::from_slice(raw_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let full_aad = build_authenticated_aad(ENVELOPE_VERSION, key_id, aad);
    let payload = Payload {
        msg: plaintext,
        aad: &full_aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut envelope = Vec::with_capacity(VERSION_LEN + KEY_ID_LEN + NONCE_LEN + ciphertext.len());
    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&key_id.to_be_bytes());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

// decrypt field from versioned envelope, returning zeroizing buffer
pub fn decrypt_field(
    keyring: &KeyRing,
    envelope: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(CryptoError::EnvelopeTooShort(envelope.len()));
    }

    let version = envelope[0];
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }

    let key_id = u16::from_be_bytes([envelope[1], envelope[2]]);
    let raw_key = keyring
        .get_key(key_id)
        .ok_or(CryptoError::KeyNotFound(key_id))?;

    let nonce_bytes = &envelope[3..15];
    let ciphertext_and_tag = &envelope[15..];

    let key = Key::<Aes256Gcm>::from_slice(raw_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let full_aad = build_authenticated_aad(version, key_id, aad);
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad: &full_aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

// generate new 256-bit api key: (pen_live_<64_hex_chars>, sha256_hash_hex)
pub fn generate_api_key() -> (String, String) {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let hex_part = hex::encode(random_bytes);
    let raw_key = format!("{API_KEY_PREFIX}{hex_part}");
    let key_hash = hash_api_key(&raw_key).expect("generated api key is always valid");
    (raw_key, key_hash)
}

// hash raw api key with sha-256 after validating prefix and lowercase hex format
pub fn hash_api_key(raw_key: &str) -> Result<String, CryptoError> {
    if raw_key.len() != API_KEY_TOTAL_LEN || !raw_key.starts_with(API_KEY_PREFIX) {
        return Err(CryptoError::InvalidApiKeyFormat);
    }

    let hex_part = &raw_key[API_KEY_PREFIX.len()..];
    if !is_lowercase_hex(hex_part) {
        return Err(CryptoError::InvalidApiKeyFormat);
    }

    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// rfc 2104 hmac-sha256 using sha2::Sha256 and zeroized pad buffers
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key_block = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(*ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(*opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_digest);
    out
}

fn decode_session_secret(
    session_secret: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let trimmed = session_secret.expose_secret().trim();
    if trimmed.len() != 64 {
        return Err(CryptoError::InvalidSessionSecret);
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(trimmed, &mut *raw).map_err(|_| CryptoError::InvalidSessionSecret)?;
    if raw.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidSessionSecret);
    }
    Ok(raw)
}

// generate session token and its keyed hmac-sha256 digest: (64_hex_chars, 64_hex_digest)
pub fn generate_session_token(
    session_secret: &SecretString,
) -> Result<(String, String), CryptoError> {
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let raw_token = hex::encode(token_bytes);
    let token_hash = hash_session_token(&raw_token, session_secret)?;

    Ok((raw_token, token_hash))
}

// validate session token format and compute keyed hmac-sha256 digest for db lookup
pub fn hash_session_token(
    raw_token: &str,
    session_secret: &SecretString,
) -> Result<String, CryptoError> {
    if raw_token.len() != 64 || !is_lowercase_hex(raw_token) {
        return Err(CryptoError::InvalidSessionTokenFormat);
    }

    let secret_bytes = decode_session_secret(session_secret)?;
    Ok(hex::encode(hmac_sha256(
        &*secret_bytes,
        raw_token.as_bytes(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY_2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn password_hash_and_verify_roundtrip() {
        let password = SecretString::new("super_secret_warehouse_pass_2026".to_string());
        let hash = hash_password(&password).expect("hash password");
        assert!(hash.starts_with("$argon2id$"));

        let ok = verify_password(&password, &hash).expect("verify password");
        assert!(ok);

        let wrong = SecretString::new("wrong_password".to_string());
        let bad = verify_password(&wrong, &hash).expect("verify wrong password");
        assert!(!bad);
    }

    #[test]
    fn field_encryption_roundtrip_with_aad() {
        let raw = format!("1:{KEY_1}");
        let keyring = KeyRing::from_env_str(1, &raw).expect("valid keyring");

        let plaintext = b"Sensitive product notes: fragile chemical compound";
        let aad = b"products:encrypted_notes:00000000-0000-0000-0000-000000000001";

        let encrypted = encrypt_field(&keyring, plaintext, aad).expect("encrypt field");

        // verify envelope layout: version 0x01, key id 1 in big-endian, 12-byte nonce
        assert_eq!(encrypted[0], 0x01);
        assert_eq!(u16::from_be_bytes([encrypted[1], encrypted[2]]), 1);
        assert!(encrypted.len() >= MIN_ENVELOPE_LEN + plaintext.len());

        let decrypted = decrypt_field(&keyring, &encrypted, aad).expect("decrypt field");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn field_encryption_key_rotation_works() {
        // encrypt with key id 1
        let kr1 = KeyRing::from_env_str(1, &format!("1:{KEY_1}")).expect("keyring 1");
        let plaintext = b"Confidential supplier discount code";
        let aad = b"products:encrypted_notes:item-uuid-42";
        let encrypted_v1 = encrypt_field(&kr1, plaintext, aad).expect("encrypt with key 1");

        // rotate active key to key id 2 while keeping key id 1 in the keyring
        let kr2 = KeyRing::from_env_str(2, &format!("1:{KEY_1}, 2:{KEY_2}")).expect("keyring 2");

        // decrypt historical item encrypted with key 1
        let decrypted_v1 = decrypt_field(&kr2, &encrypted_v1, aad).expect("decrypt old item");
        assert_eq!(decrypted_v1.as_slice(), plaintext);

        // encrypt new item with active key 2
        let encrypted_v2 = encrypt_field(&kr2, plaintext, aad).expect("encrypt with key 2");
        assert_eq!(u16::from_be_bytes([encrypted_v2[1], encrypted_v2[2]]), 2);
        let decrypted_v2 = decrypt_field(&kr2, &encrypted_v2, aad).expect("decrypt new item");
        assert_eq!(decrypted_v2.as_slice(), plaintext);
    }

    #[test]
    fn aad_transplant_attack_fails() {
        let keyring = KeyRing::from_env_str(1, &format!("1:{KEY_1}")).expect("valid keyring");
        let plaintext = b"Notes for SKU A";
        let aad_a = b"products:encrypted_notes:sku-a-uuid";
        let aad_b = b"products:encrypted_notes:sku-b-uuid";

        let encrypted = encrypt_field(&keyring, plaintext, aad_a).expect("encrypt SKU A");

        // decrypting with SKU B's AAD must fail
        let err = decrypt_field(&keyring, &encrypted, aad_b).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn tamper_attacks_are_detected() {
        let keyring = KeyRing::from_env_str(1, &format!("1:{KEY_1}")).expect("valid keyring");
        let plaintext = b"Critical security notes";
        let aad = b"products:encrypted_notes:sku-test";
        let encrypted = encrypt_field(&keyring, plaintext, aad).expect("encrypt");

        // tamper version byte
        let mut tampered_version = encrypted.clone();
        tampered_version[0] = 0x02;
        assert!(matches!(
            decrypt_field(&keyring, &tampered_version, aad).unwrap_err(),
            CryptoError::UnsupportedVersion(2)
        ));

        // tamper key id byte
        let mut tampered_key_id = encrypted.clone();
        tampered_key_id[2] ^= 0x01; // changes key id to 0
        assert!(matches!(
            decrypt_field(&keyring, &tampered_key_id, aad).unwrap_err(),
            CryptoError::KeyNotFound(0)
        ));

        // tamper ciphertext / tag byte
        let mut tampered_data = encrypted.clone();
        let last = tampered_data.len() - 1;
        tampered_data[last] ^= 0x01;
        assert!(matches!(
            decrypt_field(&keyring, &tampered_data, aad).unwrap_err(),
            CryptoError::DecryptionFailed
        ));

        // truncated envelope
        assert!(matches!(
            decrypt_field(&keyring, &encrypted[..20], aad).unwrap_err(),
            CryptoError::EnvelopeTooShort(20)
        ));
    }

    #[test]
    fn api_key_generation_and_hashing() {
        let (raw_key, hash) = generate_api_key();
        assert!(raw_key.starts_with("pen_live_"));
        assert_eq!(raw_key.len(), 73);
        assert_eq!(hash.len(), 64);

        let recomputed_hash = hash_api_key(&raw_key).expect("valid api key hash");
        assert_eq!(recomputed_hash, hash);

        // reject invalid formats (including uppercase hex)
        assert!(hash_api_key("pen_test_0123").is_err());
        assert!(hash_api_key("pen_live_short").is_err());
        assert!(hash_api_key(&raw_key.to_ascii_uppercase()).is_err());
        assert!(hash_api_key(&format!(
            "{API_KEY_PREFIX}{}",
            raw_key[API_KEY_PREFIX.len()..].to_ascii_uppercase()
        ))
        .is_err());
        assert!(hash_api_key(&format!("{raw_key}extra")).is_err());
    }

    #[test]
    fn session_token_generation_and_hashing() {
        let secret_a = SecretString::new(KEY_1.to_string());
        let secret_b = SecretString::new(KEY_2.to_string());

        let (raw_token, token_hash) =
            generate_session_token(&secret_a).expect("generate session token");
        assert_eq!(raw_token.len(), 64);
        assert_eq!(token_hash.len(), 64);

        let recomputed_hash =
            hash_session_token(&raw_token, &secret_a).expect("valid session token");
        assert_eq!(recomputed_hash, token_hash);

        let other_secret_hash = hash_session_token(&raw_token, &secret_b)
            .expect("different secret produces different hash");
        assert_ne!(other_secret_hash, token_hash);

        // reject empty, short, non-hex, and uppercase session tokens
        assert!(matches!(
            hash_session_token("", &secret_a).unwrap_err(),
            CryptoError::InvalidSessionTokenFormat
        ));
        assert!(matches!(
            hash_session_token("too_short", &secret_a).unwrap_err(),
            CryptoError::InvalidSessionTokenFormat
        ));
        assert!(matches!(
            hash_session_token(&raw_token.to_ascii_uppercase(), &secret_a).unwrap_err(),
            CryptoError::InvalidSessionTokenFormat
        ));

        // reject zero or malformed session secrets
        let zero_secret = SecretString::new("0".repeat(64));
        assert!(matches!(
            hash_session_token(&raw_token, &zero_secret).unwrap_err(),
            CryptoError::InvalidSessionSecret
        ));
        let short_secret = SecretString::new("abcd".to_string());
        assert!(matches!(
            generate_session_token(&short_secret).unwrap_err(),
            CryptoError::InvalidSessionSecret
        ));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_vectors() {
        let key1 = [0x0bu8; 20];
        let mac1 = hex::encode(hmac_sha256(&key1, b"Hi There"));
        assert_eq!(
            mac1,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        let mac2 = hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?"));
        assert_eq!(
            mac2,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn header_key_id_swap_is_rejected_by_bound_aad() {
        let kr = KeyRing::from_env_str(1, &format!("1:{KEY_1}, 2:{KEY_1}")).expect("keyring");
        let plaintext = b"Header tamper test";
        let aad = b"products:encrypted_notes:header-swap";
        let mut encrypted = encrypt_field(&kr, plaintext, aad).expect("encrypt with key 1");

        // even when key 2 exists in the keyring with identical key bytes, swapping header key_id to 2 fails auth
        encrypted[2] = 0x02;
        assert!(matches!(
            decrypt_field(&kr, &encrypted, aad).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }
}
