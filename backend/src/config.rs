// app configuration and encryption keyring validation

use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingVar(String),

    #[error("invalid integer value for {0}: {1}")]
    InvalidInt(String, std::num::ParseIntError),

    #[error("active encryption key {0} was not found in keyring")]
    ActiveKeyNotFound(u16),

    #[error("empty encryption keyring (PENELOPE_ENCRYPTION_KEYS must contain at least one key)")]
    EmptyKeyring,

    #[error("malformed key entry: '{0}' (expected <id>:<64_hex_chars>)")]
    MalformedKeyEntry(String),

    #[error("invalid key id '{0}' (must be a valid u16)")]
    InvalidKeyId(String),

    #[error("invalid key length for key id {0}: expected 64 hex characters (32 bytes), got {1}")]
    InvalidKeyLength(u16, usize),

    #[error("invalid hex characters in key id {0}: {1}")]
    InvalidHex(u16, hex::FromHexError),

    #[error("key id {0} is all zeroes, which is not permitted")]
    ZeroKeyForbidden(u16),

    #[error("session secret is too short: must be at least 32 characters, got {0}")]
    SessionSecretTooShort(usize),
}

#[derive(Clone)]
pub struct KeyRing {
    active_key_id: u16,
    keys: Arc<HashMap<u16, Zeroizing<[u8; 32]>>>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("active_key_id", &self.active_key_id)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl KeyRing {
    // parse keyring from PENELOPE_ACTIVE_KEY_ID and PENELOPE_ENCRYPTION_KEYS
    pub fn from_env_str(active_id: u16, raw_keys: &str) -> Result<Self, ConfigError> {
        let trimmed = raw_keys.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::EmptyKeyring);
        }

        let mut map = HashMap::new();

        for entry in trimmed.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            let parts: Vec<&str> = entry.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(ConfigError::MalformedKeyEntry(entry.to_string()));
            }

            let id_str = parts[0].trim();
            let hex_str = parts[1].trim();

            let id: u16 = id_str
                .parse()
                .map_err(|_| ConfigError::InvalidKeyId(id_str.to_string()))?;

            if hex_str.len() != 64 {
                return Err(ConfigError::InvalidKeyLength(id, hex_str.len()));
            }

            let mut raw_bytes = [0u8; 32];
            hex::decode_to_slice(hex_str, &mut raw_bytes)
                .map_err(|e| ConfigError::InvalidHex(id, e))?;

            // check if key is all zeroes
            if raw_bytes.iter().all(|&b| b == 0) {
                return Err(ConfigError::ZeroKeyForbidden(id));
            }

            map.insert(id, Zeroizing::new(raw_bytes));
        }

        if map.is_empty() {
            return Err(ConfigError::EmptyKeyring);
        }

        if !map.contains_key(&active_id) {
            return Err(ConfigError::ActiveKeyNotFound(active_id));
        }

        Ok(Self {
            active_key_id: active_id,
            keys: Arc::new(map),
        })
    }

    pub fn active_key_id(&self) -> u16 {
        self.active_key_id
    }

    pub fn active_key(&self) -> (u16, &[u8; 32]) {
        let key = self
            .keys
            .get(&self.active_key_id)
            .expect("active key checked at construction");
        (self.active_key_id, &**key)
    }

    pub fn get_key(&self, key_id: u16) -> Option<&[u8; 32]> {
        self.keys.get(&key_id).map(|k| &**k)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

#[derive(Clone)]
pub struct InitialAdminConfig {
    pub email: String,
    pub password: SecretString,
}

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub migration_database_url: String,
    pub run_migrations: bool,
    pub server_host: String,
    pub server_port: u16,
    pub session_secret: SecretString,
    pub cors_allowed_origins: Vec<String>,
    pub keyring: KeyRing,
    pub initial_admin: Option<InitialAdminConfig>,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("database_url", &"<redacted>")
            .field("migration_database_url", &"<redacted>")
            .field("run_migrations", &self.run_migrations)
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("session_secret", &"<redacted>")
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("keyring", &self.keyring)
            .field("initial_admin_present", &self.initial_admin.is_some())
            .finish()
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL".to_string()))?;

        let migration_database_url =
            std::env::var("MIGRATION_DATABASE_URL").unwrap_or_else(|_| database_url.clone());

        let run_migrations = std::env::var("PENELOPE_RUN_MIGRATIONS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let server_host = std::env::var("PENELOPE_HOST")
            .or_else(|_| std::env::var("SERVER_HOST"))
            .unwrap_or_else(|_| "127.0.0.1".to_string());

        let server_port = std::env::var("PENELOPE_PORT")
            .or_else(|_| std::env::var("PORT"))
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("PORT".to_string(), e))?;

        let session_secret_raw = std::env::var("SESSION_SECRET")
            .map_err(|_| ConfigError::MissingVar("SESSION_SECRET".to_string()))?;

        if session_secret_raw.trim().len() < 32 {
            return Err(ConfigError::SessionSecretTooShort(
                session_secret_raw.trim().len(),
            ));
        }
        let session_secret = SecretString::new(session_secret_raw);

        let cors_raw = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string());
        let cors_allowed_origins = cors_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let active_key_id = std::env::var("PENELOPE_ACTIVE_KEY_ID")
            .map_err(|_| ConfigError::MissingVar("PENELOPE_ACTIVE_KEY_ID".to_string()))?
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("PENELOPE_ACTIVE_KEY_ID".to_string(), e))?;

        let raw_keys = std::env::var("PENELOPE_ENCRYPTION_KEYS")
            .map_err(|_| ConfigError::MissingVar("PENELOPE_ENCRYPTION_KEYS".to_string()))?;

        let keyring = KeyRing::from_env_str(active_key_id, &raw_keys)?;

        let initial_admin = match (
            std::env::var("PENELOPE_INITIAL_ADMIN_EMAIL"),
            std::env::var("PENELOPE_INITIAL_ADMIN_PASSWORD"),
        ) {
            (Ok(email), Ok(pw)) if !email.trim().is_empty() && !pw.trim().is_empty() => {
                Some(InitialAdminConfig {
                    email: email.trim().to_string(),
                    password: SecretString::new(pw),
                })
            }
            _ => None,
        };

        Ok(Self {
            database_url,
            migration_database_url,
            run_migrations,
            server_host,
            server_port,
            session_secret,
            cors_allowed_origins,
            keyring,
            initial_admin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY_1: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_KEY_2: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const ZERO_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn single_valid_keyring_works() {
        let raw = format!("1:{VALID_KEY_1}");
        let kr = KeyRing::from_env_str(1, &raw).expect("valid keyring");
        assert_eq!(kr.active_key_id(), 1);
        assert_eq!(kr.key_count(), 1);
        assert!(kr.get_key(1).is_some());
        assert!(kr.get_key(2).is_none());
    }

    #[test]
    fn multi_key_rotation_keyring_works() {
        let raw = format!("1:{VALID_KEY_1}, 2:{VALID_KEY_2}");
        let kr = KeyRing::from_env_str(2, &raw).expect("valid keyring with rotation");
        assert_eq!(kr.active_key_id(), 2);
        assert_eq!(kr.key_count(), 2);
        assert!(kr.get_key(1).is_some());
        assert!(kr.get_key(2).is_some());
    }

    #[test]
    fn rejects_all_zero_key() {
        let raw = format!("1:{ZERO_KEY}");
        let err = KeyRing::from_env_str(1, &raw).unwrap_err();
        match err {
            ConfigError::ZeroKeyForbidden(id) => assert_eq!(id, 1),
            other => panic!("expected ZeroKeyForbidden, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_active_key_in_set() {
        let raw = format!("1:{VALID_KEY_1}");
        let err = KeyRing::from_env_str(2, &raw).unwrap_err();
        match err {
            ConfigError::ActiveKeyNotFound(id) => assert_eq!(id, 2),
            other => panic!("expected ActiveKeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_key_length() {
        let raw = "1:0123456789abcdef";
        let err = KeyRing::from_env_str(1, raw).unwrap_err();
        match err {
            ConfigError::InvalidKeyLength(id, len) => {
                assert_eq!(id, 1);
                assert_eq!(len, 16);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_hex() {
        let raw = "1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let err = KeyRing::from_env_str(1, raw).unwrap_err();
        match err {
            ConfigError::InvalidHex(id, _) => assert_eq!(id, 1),
            other => panic!("expected InvalidHex, got {other:?}"),
        }
    }

    #[test]
    fn rejects_placeholder_key_string() {
        let raw = "1:CHANGE_ME_GENERATE_64_HEX_CHAR_KEY_WITH_OPENSSL_RAND_HEX_32";
        let err = KeyRing::from_env_str(1, raw).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidKeyLength(..) | ConfigError::InvalidHex(..)
        ));
    }
}
