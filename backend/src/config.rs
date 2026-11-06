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

    #[error("placeholder value is not permitted for {0}")]
    PlaceholderForbidden(String),

    #[error("session secret invalid length: expected 64 hex characters (32 bytes), got {0}")]
    SessionSecretTooShort(usize),

    #[error("session secret must be valid hexadecimal: {0}")]
    InvalidSessionSecretHex(hex::FromHexError),

    #[error("session secret cannot be all zeroes")]
    ZeroSessionSecretForbidden,

    #[error("initial admin password is too short: must be at least 12 characters, got {0}")]
    AdminPasswordTooShort(usize),

    #[error(
        "MIGRATION_DATABASE_URL must use the migration owner role and cannot equal DATABASE_URL"
    )]
    MigrationUrlMatchesRuntimeUrl,
}

fn is_placeholder_value(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    lower.contains("change_me")
        || lower.contains("changeme")
        || lower.contains("placeholder")
        || lower.contains("your_secret")
        || lower.contains("your_password")
        || lower.contains("example_")
}

// validate that session secret is a 64-char hex string (256-bit) and not a placeholder or all zeroes
pub fn validate_session_secret(raw: &str) -> Result<SecretString, ConfigError> {
    let trimmed = raw.trim();
    if is_placeholder_value(trimmed) {
        return Err(ConfigError::PlaceholderForbidden(
            "SESSION_SECRET".to_string(),
        ));
    }
    if trimmed.len() != 64 {
        return Err(ConfigError::SessionSecretTooShort(trimmed.len()));
    }
    let decoded =
        Zeroizing::new(hex::decode(trimmed).map_err(ConfigError::InvalidSessionSecretHex)?);
    if decoded.iter().all(|&b| b == 0) {
        return Err(ConfigError::ZeroSessionSecretForbidden);
    }
    Ok(SecretString::new(trimmed.to_string()))
}

// validate initial admin bootstrap credentials against placeholder values and minimum password length
pub fn validate_initial_admin(
    email: &str,
    pw: &str,
    full_name: &str,
) -> Result<InitialAdminConfig, ConfigError> {
    let email_trimmed = email.trim();
    let pw_trimmed = pw.trim();
    let name_trimmed = full_name.trim();

    if email_trimmed.is_empty() {
        return Err(ConfigError::MissingVar(
            "INITIAL_ADMIN_EMAIL cannot be blank".to_string(),
        ));
    }
    if is_placeholder_value(email_trimmed) {
        return Err(ConfigError::PlaceholderForbidden(
            "INITIAL_ADMIN_EMAIL".to_string(),
        ));
    }

    if pw_trimmed.is_empty() {
        return Err(ConfigError::MissingVar(
            "INITIAL_ADMIN_PASSWORD cannot be blank".to_string(),
        ));
    }
    if is_placeholder_value(pw_trimmed) {
        return Err(ConfigError::PlaceholderForbidden(
            "INITIAL_ADMIN_PASSWORD".to_string(),
        ));
    }

    let pw_char_len = pw_trimmed.chars().count();
    if pw_char_len < 12 {
        return Err(ConfigError::AdminPasswordTooShort(pw_char_len));
    }

    Ok(InitialAdminConfig {
        email: email_trimmed.to_string(),
        password: SecretString::new(pw_trimmed.to_string()),
        full_name: if name_trimmed.is_empty() {
            "System Administrator".to_string()
        } else {
            name_trimmed.to_string()
        },
    })
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
    pub full_name: String,
}

impl std::fmt::Debug for InitialAdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialAdminConfig")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("full_name", &self.full_name)
            .finish()
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub migration_database_url: Option<String>,
    pub run_migrations: bool,
    pub server_host: String,
    pub server_port: u16,
    pub session_secret: SecretString,
    pub cors_allowed_origins: Vec<String>,
    pub keyring: KeyRing,
    pub initial_admin: Option<InitialAdminConfig>,
    pub default_currency_code: String,
    pub seed_demo_data: bool,
    pub session_idle_ttl_hours: u32,
    pub session_absolute_ttl_hours: u32,
    pub rate_limit_auth_per_min: u32,
    pub rate_limit_api_per_min: u32,
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
            .field("default_currency_code", &self.default_currency_code)
            .field("seed_demo_data", &self.seed_demo_data)
            .field("session_idle_ttl_hours", &self.session_idle_ttl_hours)
            .field(
                "session_absolute_ttl_hours",
                &self.session_absolute_ttl_hours,
            )
            .field("rate_limit_auth_per_min", &self.rate_limit_auth_per_min)
            .field("rate_limit_api_per_min", &self.rate_limit_api_per_min)
            .finish()
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Self::from_lookup(|key| map.get(key).cloned())
    }

    pub fn from_lookup<F>(get_var: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let database_url = get_var("DATABASE_URL")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| ConfigError::MissingVar("DATABASE_URL".to_string()))?;

        // supports both RUN_MIGRATIONS_ON_STARTUP from .sample_env.env and PENELOPE_RUN_MIGRATIONS
        let run_migrations = get_var("RUN_MIGRATIONS_ON_STARTUP")
            .or_else(|| get_var("PENELOPE_RUN_MIGRATIONS"))
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let raw_migration_url = get_var("MIGRATION_DATABASE_URL")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if let Some(ref mig_url) = raw_migration_url {
            if mig_url == &database_url {
                return Err(ConfigError::MigrationUrlMatchesRuntimeUrl);
            }
        }

        let migration_database_url = if run_migrations {
            Some(
                raw_migration_url
                    .ok_or_else(|| ConfigError::MissingVar("MIGRATION_DATABASE_URL".to_string()))?,
            )
        } else {
            raw_migration_url
        };

        // supports BACKEND_HOST from .sample_env.env, PENELOPE_HOST, and SERVER_HOST
        let server_host = get_var("BACKEND_HOST")
            .or_else(|| get_var("PENELOPE_HOST"))
            .or_else(|| get_var("SERVER_HOST"))
            .unwrap_or_else(|| "127.0.0.1".to_string());

        // supports BACKEND_PORT from .sample_env.env, PENELOPE_PORT, and PORT
        let server_port = get_var("BACKEND_PORT")
            .or_else(|| get_var("PENELOPE_PORT"))
            .or_else(|| get_var("PORT"))
            .unwrap_or_else(|| "8080".to_string())
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("PORT".to_string(), e))?;

        let session_secret_raw = get_var("SESSION_SECRET")
            .ok_or_else(|| ConfigError::MissingVar("SESSION_SECRET".to_string()))?;

        let session_secret = validate_session_secret(&session_secret_raw)?;

        // supports FRONTEND_ORIGIN from .sample_env.env and CORS_ALLOWED_ORIGINS
        let cors_raw = get_var("FRONTEND_ORIGIN")
            .or_else(|| get_var("CORS_ALLOWED_ORIGINS"))
            .unwrap_or_else(|| "http://localhost:5173,http://127.0.0.1:5173".to_string());
        let cors_allowed_origins = cors_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let active_key_id = get_var("PENELOPE_ACTIVE_KEY_ID")
            .ok_or_else(|| ConfigError::MissingVar("PENELOPE_ACTIVE_KEY_ID".to_string()))?
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("PENELOPE_ACTIVE_KEY_ID".to_string(), e))?;

        let raw_keys = get_var("PENELOPE_ENCRYPTION_KEYS")
            .ok_or_else(|| ConfigError::MissingVar("PENELOPE_ENCRYPTION_KEYS".to_string()))?;

        let keyring = KeyRing::from_env_str(active_key_id, &raw_keys)?;

        // check first-run admin bootstrap toggle and variables
        let bootstrap_enabled = get_var("BOOTSTRAP_INITIAL_ADMIN")
            .or_else(|| get_var("PENELOPE_BOOTSTRAP_INITIAL_ADMIN"))
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let initial_admin = if bootstrap_enabled {
            let email = get_var("INITIAL_ADMIN_EMAIL")
                .or_else(|| get_var("PENELOPE_INITIAL_ADMIN_EMAIL"))
                .ok_or_else(|| ConfigError::MissingVar("INITIAL_ADMIN_EMAIL".to_string()))?;

            let pw = get_var("INITIAL_ADMIN_PASSWORD")
                .or_else(|| get_var("PENELOPE_INITIAL_ADMIN_PASSWORD"))
                .ok_or_else(|| ConfigError::MissingVar("INITIAL_ADMIN_PASSWORD".to_string()))?;

            let full_name = get_var("INITIAL_ADMIN_NAME")
                .or_else(|| get_var("PENELOPE_INITIAL_ADMIN_NAME"))
                .unwrap_or_else(|| "System Administrator".to_string());

            Some(validate_initial_admin(&email, &pw, &full_name)?)
        } else {
            None
        };

        let default_currency_code =
            get_var("DEFAULT_CURRENCY_CODE").unwrap_or_else(|| "EUR".to_string());

        let seed_demo_data = get_var("SEED_DEMO_DATA")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let session_idle_ttl_hours = get_var("SESSION_IDLE_TTL_HOURS")
            .unwrap_or_else(|| "24".to_string())
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("SESSION_IDLE_TTL_HOURS".to_string(), e))?;

        let session_absolute_ttl_hours = get_var("SESSION_ABSOLUTE_TTL_HOURS")
            .unwrap_or_else(|| "168".to_string())
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("SESSION_ABSOLUTE_TTL_HOURS".to_string(), e))?;

        let rate_limit_auth_per_min = get_var("RATE_LIMIT_AUTH_PER_MIN")
            .unwrap_or_else(|| "10".to_string())
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("RATE_LIMIT_AUTH_PER_MIN".to_string(), e))?;

        let rate_limit_api_per_min = get_var("RATE_LIMIT_API_PER_MIN")
            .unwrap_or_else(|| "120".to_string())
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("RATE_LIMIT_API_PER_MIN".to_string(), e))?;

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
            default_currency_code,
            seed_demo_data,
            session_idle_ttl_hours,
            session_absolute_ttl_hours,
            rate_limit_auth_per_min,
            rate_limit_api_per_min,
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

    fn sample_env_pairs() -> Vec<(&'static str, String)> {
        vec![
            (
                "DATABASE_URL",
                "postgres://penelope_app:penelope_app_password@localhost:5432/penelope_db"
                    .to_string(),
            ),
            (
                "MIGRATION_DATABASE_URL",
                "postgres://penelope_owner:penelope_owner_password@localhost:5432/penelope_db"
                    .to_string(),
            ),
            ("BACKEND_HOST", "0.0.0.0".to_string()),
            ("BACKEND_PORT", "9090".to_string()),
            ("FRONTEND_ORIGIN", "http://localhost:3000".to_string()),
            ("RUN_MIGRATIONS_ON_STARTUP", "true".to_string()),
            ("SESSION_SECRET", VALID_KEY_2.to_string()),
            ("PENELOPE_ACTIVE_KEY_ID", "1".to_string()),
            ("PENELOPE_ENCRYPTION_KEYS", format!("1:{VALID_KEY_1}")),
            ("BOOTSTRAP_INITIAL_ADMIN", "true".to_string()),
            ("INITIAL_ADMIN_EMAIL", "boss@penelope.local".to_string()),
            (
                "INITIAL_ADMIN_PASSWORD",
                "strong_admin_pass_123".to_string(),
            ),
            ("INITIAL_ADMIN_NAME", "Lead Admin".to_string()),
        ]
    }

    #[test]
    fn app_config_parses_sample_env_variables() {
        let config = AppConfig::from_pairs(sample_env_pairs()).expect("valid app config");
        assert_eq!(config.server_host, "0.0.0.0");
        assert_eq!(config.server_port, 9090);
        assert_eq!(config.cors_allowed_origins, vec!["http://localhost:3000"]);
        assert!(config.run_migrations);
        assert!(config.initial_admin.is_some());
        let admin = config.initial_admin.unwrap();
        assert_eq!(admin.email, "boss@penelope.local");
        assert_eq!(admin.full_name, "Lead Admin");
    }

    #[test]
    fn rejects_short_session_secret() {
        let mut pairs = sample_env_pairs();
        pairs.push(("SESSION_SECRET", "too_short".to_string()));

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        match err {
            ConfigError::SessionSecretTooShort(len) => assert_eq!(len, 9),
            other => panic!("expected SessionSecretTooShort, got {other:?}"),
        }
    }

    #[test]
    fn rejects_placeholder_session_secret() {
        let mut pairs = sample_env_pairs();
        pairs.push((
            "SESSION_SECRET",
            "CHANGE_ME_GENERATE_64_CHAR_SECRET_WITH_OPENSSL_RAND_HEX_32".to_string(),
        ));

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        match err {
            ConfigError::PlaceholderForbidden(var) => assert_eq!(var, "SESSION_SECRET"),
            other => panic!("expected PlaceholderForbidden, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_hex_or_all_zero_session_secret() {
        let mut non_hex_pairs = sample_env_pairs();
        non_hex_pairs.push((
            "SESSION_SECRET",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
        ));
        let err_hex = AppConfig::from_pairs(non_hex_pairs).unwrap_err();
        assert!(matches!(err_hex, ConfigError::InvalidSessionSecretHex(_)));

        let mut zero_pairs = sample_env_pairs();
        zero_pairs.push(("SESSION_SECRET", ZERO_KEY.to_string()));
        let err_zero = AppConfig::from_pairs(zero_pairs).unwrap_err();
        assert!(matches!(err_zero, ConfigError::ZeroSessionSecretForbidden));
    }

    #[test]
    fn rejects_placeholder_or_short_initial_admin_password() {
        let mut placeholder_pairs = sample_env_pairs();
        placeholder_pairs.push((
            "INITIAL_ADMIN_PASSWORD",
            "CHANGE_ME_MIN_12_CHAR_ADMIN_PASS".to_string(),
        ));
        let err_placeholder = AppConfig::from_pairs(placeholder_pairs).unwrap_err();
        match err_placeholder {
            ConfigError::PlaceholderForbidden(var) => assert_eq!(var, "INITIAL_ADMIN_PASSWORD"),
            other => panic!("expected PlaceholderForbidden, got {other:?}"),
        }

        let mut short_pairs = sample_env_pairs();
        short_pairs.push(("INITIAL_ADMIN_PASSWORD", "short_pw_11".to_string()));
        let err_short = AppConfig::from_pairs(short_pairs).unwrap_err();
        match err_short {
            ConfigError::AdminPasswordTooShort(len) => assert_eq!(len, 11),
            other => panic!("expected AdminPasswordTooShort, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_migration_url_when_migrations_enabled() {
        let pairs: Vec<_> = sample_env_pairs()
            .into_iter()
            .filter(|(k, _)| *k != "MIGRATION_DATABASE_URL")
            .collect();

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        match err {
            ConfigError::MissingVar(var) => assert_eq!(var, "MIGRATION_DATABASE_URL"),
            other => panic!("expected MissingVar(MIGRATION_DATABASE_URL), got {other:?}"),
        }
    }

    #[test]
    fn rejects_migration_url_matching_runtime_database_url() {
        let mut pairs = sample_env_pairs();
        pairs.push((
            "MIGRATION_DATABASE_URL",
            "postgres://penelope_app:penelope_app_password@localhost:5432/penelope_db".to_string(),
        ));

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        assert!(matches!(err, ConfigError::MigrationUrlMatchesRuntimeUrl));
    }

    #[test]
    fn allows_missing_migration_url_when_migrations_disabled() {
        let mut pairs: Vec<_> = sample_env_pairs()
            .into_iter()
            .filter(|(k, _)| *k != "MIGRATION_DATABASE_URL")
            .collect();
        pairs.push(("RUN_MIGRATIONS_ON_STARTUP", "false".to_string()));

        let config = AppConfig::from_pairs(pairs).expect("valid config with migrations disabled");
        assert!(!config.run_migrations);
        assert!(config.migration_database_url.is_none());
    }
}
