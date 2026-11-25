// user, session, and api key persistence records and public responses

use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Manager,
    Operator,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Manager => "manager",
            Self::Operator => "operator",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "manager" => Ok(Self::Manager),
            "operator" => Ok(Self::Operator),
            _ => Err(AppError::validation(
                "INVALID_ROLE",
                "Role must be one of: admin, manager, operator.",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyScope {
    Manager,
    Operator,
    Readonly,
}

impl ApiKeyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manager => "manager",
            Self::Operator => "operator",
            Self::Readonly => "readonly",
        }
    }
}

impl fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApiKeyScope {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "manager" => Ok(Self::Manager),
            "operator" => Ok(Self::Operator),
            "readonly" => Ok(Self::Readonly),
            _ => Err(AppError::validation(
                "INVALID_API_KEY_SCOPE",
                "API key scope must be one of: manager, operator, readonly.",
            )),
        }
    }
}

// persistence-only record (never derives Serialize so password_hash cannot leak)
#[derive(Clone, sqlx::FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("full_name", &self.full_name)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field("is_active", &self.is_active)
            .field("last_login_at", &self.last_login_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: Role,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<UserRecord> for UserResponse {
    type Error = AppError;

    fn try_from(record: UserRecord) -> Result<Self, Self::Error> {
        let role = Role::from_str(&record.role).map_err(|_| {
            AppError::internal(format!("unexpected user role in db: {}", record.role))
        })?;
        Ok(Self {
            id: record.id,
            email: record.email,
            full_name: record.full_name,
            role,
            is_active: record.is_active,
            last_login_at: record.last_login_at,
            created_at: record.created_at,
        })
    }
}

// persistence-only record (never derives Serialize so token_hash cannot leak)
#[derive(Clone, sqlx::FromRow)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: String,
    pub user_agent: String,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"<redacted>")
            .field("ip_address", &self.ip_address)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

// persistence-only record (never derives Serialize so key_hash cannot leak)
#[derive(Clone, sqlx::FromRow)]
pub struct ApiKeyRecord {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub role_scope: String,
    pub created_by: Uuid,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for ApiKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("key_prefix", &self.key_prefix)
            .field("key_hash", &"<redacted>")
            .field("role_scope", &self.role_scope)
            .field("created_by", &self.created_by)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub role_scope: ApiKeyScope,
    pub created_by: Uuid,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TryFrom<ApiKeyRecord> for ApiKeyResponse {
    type Error = AppError;

    fn try_from(record: ApiKeyRecord) -> Result<Self, Self::Error> {
        let role_scope = ApiKeyScope::from_str(&record.role_scope).map_err(|_| {
            AppError::internal(format!(
                "unexpected api key scope in db: {}",
                record.role_scope
            ))
        })?;
        Ok(Self {
            id: record.id,
            name: record.name,
            key_prefix: record.key_prefix,
            role_scope,
            created_by: record.created_by,
            last_used_at: record.last_used_at,
            expires_at: record.expires_at,
            revoked_at: record.revoked_at,
            created_at: record.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_and_api_key_responses_strip_secret_hashes() {
        let now = Utc::now();
        let user_rec = UserRecord {
            id: Uuid::new_v4(),
            email: "manager@penelope.local".to_string(),
            full_name: "Warehouse Manager".to_string(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$secret_salt$secret_hash".to_string(),
            role: "manager".to_string(),
            is_active: true,
            last_login_at: Some(now),
            created_at: now,
        };
        assert!(!format!("{user_rec:?}").contains("secret_hash"));

        let user_res = UserResponse::try_from(user_rec).expect("valid user response");
        let user_json = serde_json::to_string(&user_res).expect("serialize user response");
        assert!(!user_json.contains("password_hash"));
        assert!(!user_json.contains("secret_hash"));
        assert!(user_json.contains("\"role\":\"manager\""));

        let key_rec = ApiKeyRecord {
            id: Uuid::new_v4(),
            name: "Floor Scanner 01".to_string(),
            key_prefix: "pen_live_a1b2c3d4".to_string(),
            key_hash: "deadbeef".repeat(8),
            role_scope: "operator".to_string(),
            created_by: Uuid::new_v4(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
        };
        assert!(!format!("{key_rec:?}").contains("deadbeef"));

        let key_res = ApiKeyResponse::try_from(key_rec).expect("valid api key response");
        let key_json = serde_json::to_string(&key_res).expect("serialize api key response");
        assert!(!key_json.contains("key_hash"));
        assert!(!key_json.contains("deadbeef"));
        assert!(key_json.contains("\"role_scope\":\"operator\""));
    }
}
