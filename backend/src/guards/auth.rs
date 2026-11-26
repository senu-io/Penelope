// authentication extractor resolving x-api-key or keyed penelope_session cookies

use crate::crypto;
use crate::error::AppError;
use crate::guards::csrf;
use crate::guards::rate_limit::client_ip_from_extensions;
use crate::models::{ApiKeyScope, Role};
use crate::services::AuditVisibilityScope;
use crate::state::AppState;
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use chrono::{DateTime, Duration, Utc};
use std::str::FromStr;
use uuid::Uuid;

pub const SESSION_COOKIE_NAME: &str = "penelope_session";
pub const API_KEY_HEADER_NAME: &str = "x-api-key";
const ACTIVITY_TOUCH_INTERVAL_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPrincipal {
    Session {
        session_id: Uuid,
        user_id: Uuid,
        email: String,
        full_name: String,
        role: Role,
    },
    ApiKey {
        api_key_id: Uuid,
        name: String,
        key_prefix: String,
        role_scope: ApiKeyScope,
        created_by: Uuid,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorContext {
    pub principal: AuthPrincipal,
    pub ip_address: String,
}

impl ActorContext {
    pub fn audit_user_id(&self) -> Option<Uuid> {
        match &self.principal {
            AuthPrincipal::Session { user_id, .. } => Some(*user_id),
            AuthPrincipal::ApiKey { .. } => None,
        }
    }

    pub fn audit_api_key_id(&self) -> Option<Uuid> {
        match &self.principal {
            AuthPrincipal::Session { .. } => None,
            AuthPrincipal::ApiKey { api_key_id, .. } => Some(*api_key_id),
        }
    }

    pub fn actor_label(&self) -> String {
        match &self.principal {
            AuthPrincipal::Session { email, .. } => email.clone(),
            AuthPrincipal::ApiKey { name, .. } => format!("key:{name}"),
        }
    }

    pub fn is_session(&self) -> bool {
        matches!(self.principal, AuthPrincipal::Session { .. })
    }

    pub fn session_id(&self) -> Option<Uuid> {
        match &self.principal {
            AuthPrincipal::Session { session_id, .. } => Some(*session_id),
            AuthPrincipal::ApiKey { .. } => None,
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(
            self.principal,
            AuthPrincipal::Session {
                role: Role::Admin,
                ..
            }
        )
    }

    pub fn can_manage(&self) -> bool {
        match &self.principal {
            AuthPrincipal::Session { role, .. } => {
                matches!(role, Role::Admin | Role::Manager)
            }
            AuthPrincipal::ApiKey { role_scope, .. } => matches!(role_scope, ApiKeyScope::Manager),
        }
    }

    pub fn can_operate(&self) -> bool {
        match &self.principal {
            AuthPrincipal::Session { .. } => true,
            AuthPrincipal::ApiKey { role_scope, .. } => {
                matches!(role_scope, ApiKeyScope::Manager | ApiKeyScope::Operator)
            }
        }
    }

    pub fn can_view_confidential_notes(&self) -> bool {
        self.can_manage()
    }

    pub fn audit_visibility_scope(&self) -> Option<AuditVisibilityScope> {
        match &self.principal {
            AuthPrincipal::Session {
                role: Role::Admin, ..
            } => Some(AuditVisibilityScope::Full),
            AuthPrincipal::Session {
                role: Role::Manager,
                ..
            }
            | AuthPrincipal::ApiKey {
                role_scope: ApiKeyScope::Manager,
                ..
            } => Some(AuditVisibilityScope::Operational),
            _ => None,
        }
    }
}

pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    for raw_header in headers.get_all(header::COOKIE) {
        let Ok(cookie_str) = raw_header.to_str() else {
            continue;
        };
        for pair in cookie_str.split(';') {
            let trimmed = pair.trim();
            if let Some((name, value)) = trimmed.split_once('=') {
                if name.trim() == SESSION_COOKIE_NAME {
                    let val = value.trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn build_session_cookie(raw_token: &str, max_age_secs: u64, secure: bool) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={raw_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn build_clear_session_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

#[derive(sqlx::FromRow)]
struct ApiKeyLookupRow {
    id: Uuid,
    name: String,
    key_prefix: String,
    role_scope: String,
    created_by: Uuid,
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct SessionLookupRow {
    session_id: Uuid,
    user_id: Uuid,
    email: String,
    full_name: String,
    role: String,
    last_active_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

async fn authenticate_api_key(
    state: &AppState,
    raw_header: &axum::http::HeaderValue,
    ip_address: String,
) -> Result<ActorContext, AppError> {
    let raw_key = raw_header
        .to_str()
        .map_err(|_| AppError::unauthorized("Invalid API key header."))?
        .trim();

    let key_hash = crypto::hash_api_key(raw_key)
        .map_err(|_| AppError::unauthorized("Invalid or revoked API key."))?;

    let row = sqlx::query_as::<_, ApiKeyLookupRow>(
        r#"
        SELECT
            k.id,
            k.name,
            k.key_prefix,
            k.role_scope,
            k.created_by,
            k.last_used_at
        FROM public.api_keys k
        JOIN public.users u ON u.id = k.created_by
        WHERE k.key_hash = $1
          AND k.revoked_at IS NULL
          AND (k.expires_at IS NULL OR k.expires_at > pg_catalog.now())
          AND u.is_active = TRUE
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::unauthorized("Invalid, expired, or revoked API key."))?;

    let role_scope = ApiKeyScope::from_str(&row.role_scope)
        .map_err(|_| AppError::internal(format!("unexpected api key scope: {}", row.role_scope)))?;

    let now = Utc::now();
    let should_touch = match row.last_used_at {
        None => true,
        Some(prev) => (now - prev).num_seconds() >= ACTIVITY_TOUCH_INTERVAL_SECS,
    };
    if should_touch {
        let _ = sqlx::query("UPDATE public.api_keys SET last_used_at = $2 WHERE id = $1")
            .bind(row.id)
            .bind(now)
            .execute(&state.db)
            .await;
    }

    Ok(ActorContext {
        principal: AuthPrincipal::ApiKey {
            api_key_id: row.id,
            name: row.name,
            key_prefix: row.key_prefix,
            role_scope,
            created_by: row.created_by,
        },
        ip_address,
    })
}

async fn authenticate_session(
    state: &AppState,
    parts: &Parts,
    ip_address: String,
) -> Result<ActorContext, AppError> {
    let raw_token = extract_session_cookie(&parts.headers)
        .ok_or_else(|| AppError::unauthorized("Authentication required."))?;

    let token_hash = crypto::hash_session_token(&raw_token, &state.config.session_secret)
        .map_err(|_| AppError::unauthorized("Invalid session token."))?;

    let row = sqlx::query_as::<_, SessionLookupRow>(
        r#"
        SELECT
            s.id AS session_id,
            u.id AS user_id,
            u.email,
            u.full_name,
            u.role,
            s.last_active_at,
            s.expires_at,
            s.created_at
        FROM public.sessions s
        JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = $1
          AND u.is_active = TRUE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::unauthorized("Invalid or expired session."))?;

    let now = Utc::now();
    let abs_ttl = Duration::hours(i64::from(state.config.session_absolute_ttl_hours));
    let absolute_deadline = row.created_at + abs_ttl;

    if now >= row.expires_at || now >= absolute_deadline {
        let _ = sqlx::query("DELETE FROM public.sessions WHERE id = $1")
            .bind(row.session_id)
            .execute(&state.db)
            .await;
        return Err(AppError::unauthorized("Session expired."));
    }

    // verify origin/referer on state-changing cookie requests
    csrf::verify_cookie_csrf(
        &parts.method,
        &parts.headers,
        &state.config.cors_allowed_origins,
    )?;

    let role = Role::from_str(&row.role)
        .map_err(|_| AppError::internal(format!("unexpected user role in db: {}", row.role)))?;

    if (now - row.last_active_at).num_seconds() >= ACTIVITY_TOUCH_INTERVAL_SECS {
        let idle_ttl = Duration::hours(i64::from(state.config.session_idle_ttl_hours));
        let next_expiry = (now + idle_ttl).min(absolute_deadline);
        let _ = sqlx::query(
            "UPDATE public.sessions SET last_active_at = $2, expires_at = $3 WHERE id = $1",
        )
        .bind(row.session_id)
        .bind(now)
        .bind(next_expiry)
        .execute(&state.db)
        .await;
    }

    Ok(ActorContext {
        principal: AuthPrincipal::Session {
            session_id: row.session_id,
            user_id: row.user_id,
            email: row.email,
            full_name: row.full_name,
            role,
        },
        ip_address,
    })
}

#[async_trait]
impl FromRequestParts<AppState> for ActorContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip_address = client_ip_from_extensions(&parts.extensions).unwrap_or_default();

        // when x-api-key header is present, never fall back to session cookie
        if let Some(raw_api_key) = parts.headers.get(API_KEY_HEADER_NAME) {
            return authenticate_api_key(state, raw_api_key, ip_address).await;
        }

        authenticate_session(state, parts, ip_address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_session_cookie_from_single_and_multiple_headers() {
        let mut single = HeaderMap::new();
        single.insert(
            header::COOKIE,
            "theme=light; penelope_session=abc123token; foo=bar"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_session_cookie(&single).as_deref(),
            Some("abc123token")
        );

        let mut multi = HeaderMap::new();
        multi.append(header::COOKIE, "other=1".parse().unwrap());
        multi.append(
            header::COOKIE,
            "penelope_session=second_header_token".parse().unwrap(),
        );
        assert_eq!(
            extract_session_cookie(&multi).as_deref(),
            Some("second_header_token")
        );

        let empty = HeaderMap::new();
        assert!(extract_session_cookie(&empty).is_none());
    }

    #[test]
    fn builds_session_and_clear_cookies_with_optional_secure_flag() {
        let http_cookie = build_session_cookie("deadbeef", 86400, false);
        assert_eq!(
            http_cookie,
            "penelope_session=deadbeef; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400"
        );
        assert!(!http_cookie.contains("Secure"));

        let https_cookie = build_session_cookie("deadbeef", 3600, true);
        assert!(https_cookie.ends_with("; Secure"));

        let clear_http = build_clear_session_cookie(false);
        assert_eq!(
            clear_http,
            "penelope_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
        );
        let clear_https = build_clear_session_cookie(true);
        assert!(clear_https.ends_with("; Secure"));
    }

    #[test]
    fn actor_context_enforces_exclusive_audit_ids_and_capabilities() {
        let uid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let session_admin = ActorContext {
            principal: AuthPrincipal::Session {
                session_id: sid,
                user_id: uid,
                email: "boss@penelope.local".to_string(),
                full_name: "Lead Admin".to_string(),
                role: Role::Admin,
            },
            ip_address: "127.0.0.1".to_string(),
        };
        assert_eq!(session_admin.audit_user_id(), Some(uid));
        assert_eq!(session_admin.audit_api_key_id(), None);
        assert_eq!(session_admin.session_id(), Some(sid));
        assert!(session_admin.is_session());
        assert!(session_admin.is_admin());
        assert!(session_admin.can_manage());
        assert!(session_admin.can_operate());
        assert!(session_admin.can_view_confidential_notes());
        assert_eq!(
            session_admin.audit_visibility_scope(),
            Some(AuditVisibilityScope::Full)
        );
        assert_eq!(session_admin.actor_label(), "boss@penelope.local");

        let kid = Uuid::new_v4();
        let key_ro = ActorContext {
            principal: AuthPrincipal::ApiKey {
                api_key_id: kid,
                name: "BI Reader".to_string(),
                key_prefix: "pen_live_00001111".to_string(),
                role_scope: ApiKeyScope::Readonly,
                created_by: uid,
            },
            ip_address: "10.0.0.5".to_string(),
        };
        assert_eq!(key_ro.audit_user_id(), None);
        assert_eq!(key_ro.audit_api_key_id(), Some(kid));
        assert_eq!(key_ro.session_id(), None);
        assert!(!key_ro.is_session());
        assert!(!key_ro.is_admin());
        assert!(!key_ro.can_manage());
        assert!(!key_ro.can_operate());
        assert!(!key_ro.can_view_confidential_notes());
        assert_eq!(key_ro.audit_visibility_scope(), None);
        assert_eq!(key_ro.actor_label(), "key:BI Reader");
    }
}
