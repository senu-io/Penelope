use secrecy::SecretString;
use sqlx::postgres::PgConnectOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::str::FromStr;
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

    #[error("initial admin password is too long: max 256 bytes, got {0}")]
    AdminPasswordTooLong(usize),

    #[error("initial admin full name must be at most 120 characters")]
    InvalidAdminName,

    #[error(
        "MIGRATION_DATABASE_URL must use the migration owner role and cannot equal DATABASE_URL"
    )]
    MigrationUrlMatchesRuntimeUrl,

    #[error("invalid database connection url for {0}")]
    InvalidDatabaseUrl(String),

    #[error("invalid database role for {var_name}: expected '{expected}', got '{actual}'")]
    InvalidDatabaseRole {
        var_name: String,
        expected: String,
        actual: String,
    },

    #[error("live database role verification failed: {0}")]
    DatabaseRoleVerificationFailed(String),

    #[error("duplicate encryption key id {0} in PENELOPE_ENCRYPTION_KEYS")]
    DuplicateKeyId(u16),

    #[error("invalid server port: {0} (must be between 1 and 65535)")]
    InvalidPort(u16),

    #[error("invalid session ttl configuration: {0}")]
    InvalidTtl(String),

    #[error("invalid rate limit configuration: {0}")]
    InvalidRateLimit(String),

    #[error("unsupported default currency '{0}' (only EUR is supported)")]
    UnsupportedCurrency(String),

    #[error("invalid initial admin email '{0}'")]
    InvalidAdminEmail(String),

    #[error("invalid boolean value for {var_name}: '{value}' (expected true, false, 1, or 0)")]
    InvalidBool { var_name: String, value: String },

    #[error("FRONTEND_ORIGIN must contain at least one valid origin")]
    EmptyCorsOrigins,

    #[error("invalid cors origin '{0}' (expected scheme://host[:port] with http or https and no path or wildcard)")]
    InvalidCorsOrigin(String),
}

pub fn validate_db_url_role(
    var_name: &str,
    url: &str,
    expected_role: &str,
) -> Result<(), ConfigError> {
    if is_placeholder_value(url) {
        return Err(ConfigError::PlaceholderForbidden(var_name.to_string()));
    }
    let opts = PgConnectOptions::from_str(url)
        .map_err(|_| ConfigError::InvalidDatabaseUrl(var_name.to_string()))?;
    let actual_user = opts.get_username();
    if actual_user != expected_role {
        return Err(ConfigError::InvalidDatabaseRole {
            var_name: var_name.to_string(),
            expected: expected_role.to_string(),
            actual: actual_user.to_string(),
        });
    }
    Ok(())
}

pub async fn verify_pool_role(pool: &PgPool, expected_role: &str) -> Result<(), ConfigError> {
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await
        .map_err(|e| ConfigError::DatabaseRoleVerificationFailed(e.to_string()))?;

    if current_user != expected_role {
        return Err(ConfigError::DatabaseRoleVerificationFailed(format!(
            "expected connected role '{expected_role}', got '{current_user}'"
        )));
    }
    Ok(())
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

pub fn normalize_and_validate_email(raw: &str) -> Result<String, &'static str> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 254
        || normalized
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("Email must be a valid address up to 254 characters without spaces.");
    }

    let parts: Vec<&str> = normalized.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("Email must contain a valid local part and domain.");
    }

    let local = parts[0];
    let domain = parts[1];

    if local.len() > 64 || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err("Email must contain a valid local part and domain.");
    }

    if !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return Err("Email domain must be valid.");
    }

    Ok(normalized)
}

pub fn validate_initial_admin(
    email: &str,
    pw: &str,
    full_name: &str,
) -> Result<InitialAdminConfig, ConfigError> {
    let email_trimmed = email.trim();
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
    let normalized_email = normalize_and_validate_email(email_trimmed)
        .map_err(|_| ConfigError::InvalidAdminEmail(email_trimmed.to_string()))?;

    if pw.trim().is_empty() {
        return Err(ConfigError::MissingVar(
            "INITIAL_ADMIN_PASSWORD cannot be blank".to_string(),
        ));
    }
    if is_placeholder_value(pw) {
        return Err(ConfigError::PlaceholderForbidden(
            "INITIAL_ADMIN_PASSWORD".to_string(),
        ));
    }

    let pw_char_len = pw.chars().count();
    if pw_char_len < 12 {
        return Err(ConfigError::AdminPasswordTooShort(pw_char_len));
    }
    if pw.len() > 256 {
        return Err(ConfigError::AdminPasswordTooLong(pw.len()));
    }

    let name_trimmed = full_name.trim();
    if name_trimmed.chars().count() > 120 {
        return Err(ConfigError::InvalidAdminName);
    }

    Ok(InitialAdminConfig {
        email: normalized_email,
        // keep leading/trailing spaces intact so admin creation and login hash the exact same bytes
        password: SecretString::new(pw.to_string()),
        full_name: if name_trimmed.is_empty() {
            "System Administrator".to_string()
        } else {
            name_trimmed.to_string()
        },
    })
}

fn parse_bool_var(var_name: &str, raw: Option<String>, default: bool) -> Result<bool, ConfigError> {
    let Some(val) = raw else {
        return Ok(default);
    };
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError::InvalidBool {
            var_name: var_name.to_string(),
            value: trimmed.to_string(),
        }),
    }
}

fn is_valid_host_chars(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

pub fn validate_cors_origin(raw: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.chars().any(char::is_control) {
        return Err(ConfigError::InvalidCorsOrigin(raw.to_string()));
    }

    let (scheme, rest) = if let Some(after) = trimmed.strip_prefix("http://") {
        ("http", after)
    } else if let Some(after) = trimmed.strip_prefix("https://") {
        ("https", after)
    } else if let Some((raw_scheme, after)) = trimmed.split_once("://") {
        let lower_scheme = raw_scheme.to_ascii_lowercase();
        if lower_scheme != "http" && lower_scheme != "https" {
            return Err(ConfigError::InvalidCorsOrigin(raw.to_string()));
        }
        if lower_scheme == "http" {
            ("http", after)
        } else {
            ("https", after)
        }
    } else {
        return Err(ConfigError::InvalidCorsOrigin(raw.to_string()));
    };

    if rest.is_empty()
        || rest
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@' | '*'))
    {
        return Err(ConfigError::InvalidCorsOrigin(raw.to_string()));
    }

    let authority_valid = if let Some(after_bracket) = rest.strip_prefix('[') {
        if let Some((host, port_part)) = after_bracket.split_once(']') {
            let valid_ipv6 =
                !host.is_empty() && host.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
            if !valid_ipv6 {
                false
            } else if port_part.is_empty() {
                true
            } else if let Some(port_str) = port_part.strip_prefix(':') {
                port_str.parse::<u16>().map(|p| p > 0).unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        }
    } else if let Some((host, port_str)) = rest.rsplit_once(':') {
        is_valid_host_chars(host) && port_str.parse::<u16>().map(|p| p > 0).unwrap_or(false)
    } else {
        is_valid_host_chars(rest)
    };

    if !authority_valid {
        return Err(ConfigError::InvalidCorsOrigin(raw.to_string()));
    }

    Ok(format!("{scheme}://{}", rest.to_ascii_lowercase()))
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

            if map.contains_key(&id) {
                return Err(ConfigError::DuplicateKeyId(id));
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
    pub cookie_secure: bool,
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
            .field("cookie_secure", &self.cookie_secure)
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

        validate_db_url_role("DATABASE_URL", &database_url, "penelope_app")?;

        let run_migrations = parse_bool_var(
            "RUN_MIGRATIONS_ON_STARTUP",
            get_var("RUN_MIGRATIONS_ON_STARTUP"),
            false,
        )?;

        let raw_migration_url = get_var("MIGRATION_DATABASE_URL")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        if let Some(ref mig_url) = raw_migration_url {
            if mig_url == &database_url {
                return Err(ConfigError::MigrationUrlMatchesRuntimeUrl);
            }
            validate_db_url_role("MIGRATION_DATABASE_URL", mig_url, "penelope_owner")?;
        }

        let migration_database_url = if run_migrations {
            Some(
                raw_migration_url
                    .ok_or_else(|| ConfigError::MissingVar("MIGRATION_DATABASE_URL".to_string()))?,
            )
        } else {
            raw_migration_url
        };

        let server_host = get_var("BACKEND_HOST")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let server_port = get_var("BACKEND_PORT")
            .unwrap_or_else(|| "8080".to_string())
            .trim()
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("BACKEND_PORT".to_string(), e))?;
        if server_port == 0 {
            return Err(ConfigError::InvalidPort(server_port));
        }

        let session_secret_raw = get_var("SESSION_SECRET")
            .ok_or_else(|| ConfigError::MissingVar("SESSION_SECRET".to_string()))?;

        let session_secret = validate_session_secret(&session_secret_raw)?;

        let cors_raw =
            get_var("FRONTEND_ORIGIN").unwrap_or_else(|| "http://localhost:5173".to_string());
        let cors_allowed_origins: Vec<String> = cors_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(validate_cors_origin)
            .collect::<Result<Vec<_>, _>>()?;
        if cors_allowed_origins.is_empty() {
            return Err(ConfigError::EmptyCorsOrigins);
        }

        let active_key_id = get_var("PENELOPE_ACTIVE_KEY_ID")
            .ok_or_else(|| ConfigError::MissingVar("PENELOPE_ACTIVE_KEY_ID".to_string()))?
            .trim()
            .parse::<u16>()
            .map_err(|e| ConfigError::InvalidInt("PENELOPE_ACTIVE_KEY_ID".to_string(), e))?;

        let raw_keys = get_var("PENELOPE_ENCRYPTION_KEYS")
            .ok_or_else(|| ConfigError::MissingVar("PENELOPE_ENCRYPTION_KEYS".to_string()))?;

        let keyring = KeyRing::from_env_str(active_key_id, &raw_keys)?;

        let bootstrap_enabled = parse_bool_var(
            "BOOTSTRAP_INITIAL_ADMIN",
            get_var("BOOTSTRAP_INITIAL_ADMIN"),
            false,
        )?;

        let initial_admin = if bootstrap_enabled {
            let email = get_var("INITIAL_ADMIN_EMAIL")
                .ok_or_else(|| ConfigError::MissingVar("INITIAL_ADMIN_EMAIL".to_string()))?;

            let pw = get_var("INITIAL_ADMIN_PASSWORD")
                .ok_or_else(|| ConfigError::MissingVar("INITIAL_ADMIN_PASSWORD".to_string()))?;

            let full_name =
                get_var("INITIAL_ADMIN_NAME").unwrap_or_else(|| "System Administrator".to_string());

            Some(validate_initial_admin(&email, &pw, &full_name)?)
        } else {
            None
        };

        let default_currency_code = get_var("DEFAULT_CURRENCY_CODE")
            .unwrap_or_else(|| "EUR".to_string())
            .trim()
            .to_ascii_uppercase();
        if default_currency_code != "EUR" {
            return Err(ConfigError::UnsupportedCurrency(default_currency_code));
        }

        let seed_demo_data = parse_bool_var("SEED_DEMO_DATA", get_var("SEED_DEMO_DATA"), false)?;

        let cookie_secure = parse_bool_var("COOKIE_SECURE", get_var("COOKIE_SECURE"), false)?;

        let session_idle_ttl_hours = get_var("SESSION_IDLE_TTL_HOURS")
            .unwrap_or_else(|| "24".to_string())
            .trim()
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("SESSION_IDLE_TTL_HOURS".to_string(), e))?;

        let session_absolute_ttl_hours = get_var("SESSION_ABSOLUTE_TTL_HOURS")
            .unwrap_or_else(|| "168".to_string())
            .trim()
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("SESSION_ABSOLUTE_TTL_HOURS".to_string(), e))?;

        if session_idle_ttl_hours == 0 || session_absolute_ttl_hours == 0 {
            return Err(ConfigError::InvalidTtl(
                "SESSION_IDLE_TTL_HOURS and SESSION_ABSOLUTE_TTL_HOURS must be > 0".to_string(),
            ));
        }
        if session_idle_ttl_hours > session_absolute_ttl_hours {
            return Err(ConfigError::InvalidTtl(format!(
                "SESSION_IDLE_TTL_HOURS ({session_idle_ttl_hours}) cannot exceed SESSION_ABSOLUTE_TTL_HOURS ({session_absolute_ttl_hours})"
            )));
        }

        let rate_limit_auth_per_min = get_var("RATE_LIMIT_AUTH_PER_MIN")
            .unwrap_or_else(|| "10".to_string())
            .trim()
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("RATE_LIMIT_AUTH_PER_MIN".to_string(), e))?;

        let rate_limit_api_per_min = get_var("RATE_LIMIT_API_PER_MIN")
            .unwrap_or_else(|| "120".to_string())
            .trim()
            .parse::<u32>()
            .map_err(|e| ConfigError::InvalidInt("RATE_LIMIT_API_PER_MIN".to_string(), e))?;

        if rate_limit_auth_per_min == 0 || rate_limit_api_per_min == 0 {
            return Err(ConfigError::InvalidRateLimit(
                "RATE_LIMIT_AUTH_PER_MIN and RATE_LIMIT_API_PER_MIN must be > 0".to_string(),
            ));
        }

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
            cookie_secure,
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
                "postgres://penelope_app:penelope_app_password@127.0.0.1:5432/penelope_db"
                    .to_string(),
            ),
            (
                "MIGRATION_DATABASE_URL",
                "postgres://penelope_owner:penelope_owner_password@127.0.0.1:5432/penelope_db"
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
            "postgres://penelope_app:penelope_app_password@127.0.0.1:5432/penelope_db".to_string(),
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

    #[test]
    fn rejects_superuser_or_wrong_role_in_migration_url() {
        let mut pairs = sample_env_pairs();
        pairs.push((
            "MIGRATION_DATABASE_URL",
            "postgres://postgres:penelope_owner_password@127.0.0.1:5432/penelope_db".to_string(),
        ));

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        match err {
            ConfigError::InvalidDatabaseRole {
                var_name,
                expected,
                actual,
            } => {
                assert_eq!(var_name, "MIGRATION_DATABASE_URL");
                assert_eq!(expected, "penelope_owner");
                assert_eq!(actual, "postgres");
            }
            other => panic!("expected InvalidDatabaseRole, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_role_in_runtime_database_url() {
        let mut pairs = sample_env_pairs();
        pairs.push((
            "DATABASE_URL",
            "postgres://penelope_owner:penelope_owner_password@127.0.0.1:5432/penelope_db"
                .to_string(),
        ));

        let err = AppConfig::from_pairs(pairs).unwrap_err();
        match err {
            ConfigError::InvalidDatabaseRole {
                var_name,
                expected,
                actual,
            } => {
                assert_eq!(var_name, "DATABASE_URL");
                assert_eq!(expected, "penelope_app");
                assert_eq!(actual, "penelope_owner");
            }
            other => panic!("expected InvalidDatabaseRole, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_key_ids_in_keyring() {
        let raw = format!("1:{VALID_KEY_1}, 1:{VALID_KEY_2}");
        let err = KeyRing::from_env_str(1, &raw).unwrap_err();
        match err {
            ConfigError::DuplicateKeyId(id) => assert_eq!(id, 1),
            other => panic!("expected DuplicateKeyId, got {other:?}"),
        }
    }

    #[test]
    fn rejects_placeholder_db_url_passwords() {
        let mut app_pairs = sample_env_pairs();
        app_pairs.push((
            "DATABASE_URL",
            "postgres://penelope_app:CHANGE_ME_APP_PASSWORD@127.0.0.1:5432/penelope_db".to_string(),
        ));
        let err_app = AppConfig::from_pairs(app_pairs).unwrap_err();
        match err_app {
            ConfigError::PlaceholderForbidden(var) => assert_eq!(var, "DATABASE_URL"),
            other => panic!("expected PlaceholderForbidden, got {other:?}"),
        }

        let mut mig_pairs = sample_env_pairs();
        mig_pairs.push((
            "MIGRATION_DATABASE_URL",
            "postgres://penelope_owner:CHANGE_ME_OWNER_PASSWORD@127.0.0.1:5432/penelope_db"
                .to_string(),
        ));
        let err_mig = AppConfig::from_pairs(mig_pairs).unwrap_err();
        match err_mig {
            ConfigError::PlaceholderForbidden(var) => assert_eq!(var, "MIGRATION_DATABASE_URL"),
            other => panic!("expected PlaceholderForbidden, got {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_port_and_invalid_runtime_bounds() {
        let mut zero_port = sample_env_pairs();
        zero_port.push(("BACKEND_PORT", "0".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(zero_port).unwrap_err(),
            ConfigError::InvalidPort(0)
        ));

        let mut bad_port = sample_env_pairs();
        bad_port.push(("BACKEND_PORT", "not_a_port".to_string()));
        match AppConfig::from_pairs(bad_port).unwrap_err() {
            ConfigError::InvalidInt(var, _) => assert_eq!(var, "BACKEND_PORT"),
            other => panic!("expected InvalidInt(BACKEND_PORT), got {other:?}"),
        }

        let mut zero_ttl = sample_env_pairs();
        zero_ttl.push(("SESSION_IDLE_TTL_HOURS", "0".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(zero_ttl).unwrap_err(),
            ConfigError::InvalidTtl(_)
        ));

        let mut inverted_ttl = sample_env_pairs();
        inverted_ttl.push(("SESSION_IDLE_TTL_HOURS", "48".to_string()));
        inverted_ttl.push(("SESSION_ABSOLUTE_TTL_HOURS", "24".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(inverted_ttl).unwrap_err(),
            ConfigError::InvalidTtl(_)
        ));

        let mut zero_rate = sample_env_pairs();
        zero_rate.push(("RATE_LIMIT_AUTH_PER_MIN", "0".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(zero_rate).unwrap_err(),
            ConfigError::InvalidRateLimit(_)
        ));

        let mut bad_currency = sample_env_pairs();
        bad_currency.push(("DEFAULT_CURRENCY_CODE", "USD".to_string()));
        match AppConfig::from_pairs(bad_currency).unwrap_err() {
            ConfigError::UnsupportedCurrency(cur) => assert_eq!(cur, "USD"),
            other => panic!("expected UnsupportedCurrency, got {other:?}"),
        }

        let mut bad_email = sample_env_pairs();
        bad_email.push(("INITIAL_ADMIN_EMAIL", "not-an-email".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(bad_email).unwrap_err(),
            ConfigError::InvalidAdminEmail(_)
        ));
    }

    #[test]
    fn cookie_secure_defaults_false_and_parses_strict_booleans() {
        let default_cfg = AppConfig::from_pairs(sample_env_pairs()).expect("default config");
        assert!(!default_cfg.cookie_secure);

        for raw in ["true", "TRUE", "1", " 1 "] {
            let mut pairs = sample_env_pairs();
            pairs.push(("COOKIE_SECURE", raw.to_string()));
            let cfg = AppConfig::from_pairs(pairs).expect("truthy cookie_secure");
            assert!(cfg.cookie_secure, "expected true for {raw}");
        }

        for raw in ["false", "FALSE", "0", " 0 ", ""] {
            let mut pairs = sample_env_pairs();
            pairs.push(("COOKIE_SECURE", raw.to_string()));
            let cfg = AppConfig::from_pairs(pairs).expect("falsy cookie_secure");
            assert!(!cfg.cookie_secure, "expected false for {raw}");
        }

        for bad in ["yes", "no", "ture", "2"] {
            let mut pairs = sample_env_pairs();
            pairs.push(("COOKIE_SECURE", bad.to_string()));
            let err = AppConfig::from_pairs(pairs).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidBool { ref var_name, .. } if var_name == "COOKIE_SECURE"
                ),
                "expected InvalidBool for {bad}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_bool_on_other_flags() {
        let mut pairs = sample_env_pairs();
        pairs.push(("RUN_MIGRATIONS_ON_STARTUP", "yes".to_string()));
        let err = AppConfig::from_pairs(pairs).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidBool { ref var_name, ref value }
                if var_name == "RUN_MIGRATIONS_ON_STARTUP" && value == "yes"
        ));
    }

    #[test]
    fn validates_and_normalizes_cors_origins() {
        let mut ok_pairs = sample_env_pairs();
        ok_pairs.push((
            "FRONTEND_ORIGIN",
            "HTTP://Localhost:5173, https://wms.example.com:8443".to_string(),
        ));
        let cfg = AppConfig::from_pairs(ok_pairs).expect("normalized origins");
        assert_eq!(
            cfg.cors_allowed_origins,
            vec!["http://localhost:5173", "https://wms.example.com:8443"]
        );

        let mut empty_pairs = sample_env_pairs();
        empty_pairs.push(("FRONTEND_ORIGIN", "  , ".to_string()));
        assert!(matches!(
            AppConfig::from_pairs(empty_pairs).unwrap_err(),
            ConfigError::EmptyCorsOrigins
        ));

        for bad in [
            "*",
            "http://localhost:5173/",
            "http://localhost:5173/app",
            "ftp://wms.example.com",
            "http://localhost:0",
            "http://localhost:99999",
            "http://user@localhost:5173",
        ] {
            let mut bad_pairs = sample_env_pairs();
            bad_pairs.push(("FRONTEND_ORIGIN", bad.to_string()));
            let err = AppConfig::from_pairs(bad_pairs).unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidCorsOrigin(_)),
                "expected InvalidCorsOrigin for {bad}, got {err:?}"
            );
        }
    }

    #[test]
    fn initial_admin_email_is_lowercased() {
        let mut pairs = sample_env_pairs();
        pairs.push((
            "INITIAL_ADMIN_EMAIL",
            "Boss.User@Penelope.Local".to_string(),
        ));
        let cfg = AppConfig::from_pairs(pairs).expect("valid config");
        assert_eq!(cfg.initial_admin.unwrap().email, "boss.user@penelope.local");
    }

    #[test]
    fn initial_admin_preserves_password_spaces_and_enforces_email_and_length_bounds() {
        use secrecy::ExposeSecret;

        let admin =
            validate_initial_admin("Lead.Admin@Penelope.Local", " padded secret 123 ", "Admin")
                .expect("valid admin with spaces in password");
        assert_eq!(admin.password.expose_secret(), " padded secret 123 ");

        let too_long_pw = "a".repeat(257);
        assert!(matches!(
            validate_initial_admin("lead@penelope.local", &too_long_pw, "Admin").unwrap_err(),
            ConfigError::AdminPasswordTooLong(257)
        ));

        let too_long_name = "n".repeat(121);
        assert!(matches!(
            validate_initial_admin("lead@penelope.local", "valid_password_123", &too_long_name)
                .unwrap_err(),
            ConfigError::InvalidAdminName
        ));

        for bad_email in [
            "admin@localhost",
            "a@b..c",
            "a@b.c\x00",
            ".lead@penelope.local",
            "lead..user@penelope.local",
        ] {
            assert!(
                matches!(
                    validate_initial_admin(bad_email, "valid_password_123", "Admin").unwrap_err(),
                    ConfigError::InvalidAdminEmail(_)
                ),
                "expected InvalidAdminEmail for {bad_email:?}"
            );
        }
    }
}
