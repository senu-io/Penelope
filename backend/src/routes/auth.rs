use crate::crypto;
use crate::error::AppError;
use crate::guards::{
    build_clear_session_cookie, build_session_cookie, csrf, AppJson, AuthPrincipal,
    AuthenticatedActor, ClientIp, RequireSession,
};
use crate::models::{ApiKeyRecord, ApiKeyResponse, UserRecord, UserResponse};
use crate::services::{AuditEventInput, AuditService};
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::OnceLock;
use uuid::Uuid;

static DUMMY_ARGON2_HASH: OnceLock<String> = OnceLock::new();

fn dummy_password_hash() -> &'static str {
    DUMMY_ARGON2_HASH.get_or_init(|| {
        let placeholder = SecretString::new("penelope_dummy_timing_balance_secret".to_string());
        crypto::hash_password(&placeholder).expect("hash static dummy password")
    })
}

fn extract_user_agent(headers: &HeaderMap) -> String {
    let Some(val) = headers.get(header::USER_AGENT) else {
        return String::new();
    };
    let Ok(s) = val.to_str() else {
        return String::new();
    };
    s.trim().chars().take(512).collect()
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MePermissions {
    pub is_admin: bool,
    pub can_manage: bool,
    pub can_operate: bool,
    pub can_view_confidential_notes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MeResponse {
    pub auth_type: &'static str,
    pub effective_role: String,
    pub permissions: MePermissions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<ApiKeyResponse>,
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip_address): ClientIp,
    headers: HeaderMap,
    AppJson(payload): AppJson<LoginRequest>,
) -> Result<Response, AppError> {
    csrf::verify_login_origin(&headers, &state.config.cors_allowed_origins)?;

    let email = payload.email.trim().to_ascii_lowercase();
    if email.is_empty()
        || email.len() > 254
        || email.chars().any(char::is_control)
        || payload.password.is_empty()
        || payload.password.len() > 256
    {
        return Err(AppError::validation(
            "INVALID_LOGIN_INPUT",
            "Email and password are required and must be within valid length bounds.",
        ));
    }
    let password = SecretString::new(payload.password);

    let maybe_user = sqlx::query_as::<_, UserRecord>(
        r#"
        SELECT
            id,
            email,
            full_name,
            password_hash,
            role,
            is_active,
            last_login_at,
            created_at
        FROM public.users
        WHERE email = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    // always verify against a real or dummy argon2id hash so timing stays uniform
    let target_hash = match &maybe_user {
        Some(user) if user.is_active => user.password_hash.clone(),
        _ => dummy_password_hash().to_string(),
    };

    let pw_clone = password.clone();
    let password_ok =
        match tokio::task::spawn_blocking(move || crypto::verify_password(&pw_clone, &target_hash))
            .await
            .map_err(|e| AppError::internal(format!("password verify task failed: {e}")))?
        {
            Ok(matched) => matched,
            Err(err) => {
                tracing::warn!("password hash verification failed unexpectedly: {}", err);
                false
            }
        };

    let authenticated_user = match maybe_user {
        Some(user) if user.is_active && password_ok => user,
        other => {
            let (entity_id, reason) = match other {
                None => (None, "user_not_found"),
                Some(u) if !u.is_active => (Some(u.id.to_string()), "user_inactive"),
                Some(u) => (Some(u.id.to_string()), "invalid_password"),
            };

            if let Err(err) = AuditService::record_standalone_event(
                &state.db,
                &AuditEventInput {
                    actor_user_id: None,
                    actor_api_key_id: None,
                    actor_label: format!("anonymous:{email}"),
                    action: "auth.login.failure".to_string(),
                    entity_type: "auth".to_string(),
                    entity_id,
                    ip_address,
                    details: json!({
                        "email": email,
                        "reason": reason
                    }),
                },
            )
            .await
            {
                tracing::warn!("failed to record auth.login.failure audit event: {}", err);
            }

            return Err(AppError::unauthorized("Invalid email or password."));
        }
    };

    let _ = password.expose_secret();
    let (raw_token, token_hash) = crypto::generate_session_token(&state.config.session_secret)
        .map_err(|e| AppError::internal(format!("failed to generate session token: {e}")))?;

    let now = Utc::now();
    let idle_hours = i64::from(state.config.session_idle_ttl_hours);
    // cookie max-age follows the 7d absolute ttl so sliding renewal works without re-setting cookies
    let abs_secs = u64::from(state.config.session_absolute_ttl_hours) * 3600;
    let expires_at = now + Duration::hours(idle_hours);
    let session_id = Uuid::new_v4();
    let user_agent = extract_user_agent(&headers);

    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO public.sessions (
            id, user_id, token_hash, ip_address, user_agent, last_active_at, expires_at, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $6)
        "#,
    )
    .bind(session_id)
    .bind(authenticated_user.id)
    .bind(&token_hash)
    .bind(&ip_address)
    .bind(&user_agent)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    let updated_user = sqlx::query_as::<_, UserRecord>(
        r#"
        UPDATE public.users
        SET last_login_at = $2
        WHERE id = $1
        RETURNING
            id,
            email,
            full_name,
            password_hash,
            role,
            is_active,
            last_login_at,
            created_at
        "#,
    )
    .bind(authenticated_user.id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(updated_user.id),
            actor_api_key_id: None,
            actor_label: updated_user.email.clone(),
            action: "auth.login.success".to_string(),
            entity_type: "auth".to_string(),
            entity_id: Some(session_id.to_string()),
            ip_address,
            details: json!({
                "session_id": session_id,
                "role": updated_user.role
            }),
        },
    )
    .await?;

    tx.commit().await?;

    let user_res = UserResponse::try_from(updated_user)?;
    let cookie = build_session_cookie(&raw_token, abs_secs, state.config.cookie_secure);
    let cookie_val = HeaderValue::from_str(&cookie)
        .map_err(|e| AppError::internal(format!("invalid session cookie header: {e}")))?;

    let mut res = (StatusCode::OK, Json(user_res)).into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie_val);
    Ok(res)
}

pub async fn logout(
    State(state): State<AppState>,
    RequireSession(actor): RequireSession,
) -> Result<Response, AppError> {
    let AuthPrincipal::Session {
        session_id,
        user_id,
        email,
        ..
    } = actor.principal
    else {
        return Err(AppError::forbidden("Interactive session required."));
    };

    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM public.sessions WHERE id = $1")
        .bind(session_id)
        .execute(&mut *tx)
        .await?;

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(user_id),
            actor_api_key_id: None,
            actor_label: email,
            action: "auth.logout".to_string(),
            entity_type: "auth".to_string(),
            entity_id: Some(session_id.to_string()),
            ip_address: actor.ip_address,
            details: json!({
                "session_id": session_id
            }),
        },
    )
    .await?;

    tx.commit().await?;

    let clear_cookie = build_clear_session_cookie(state.config.cookie_secure);
    let cookie_val = HeaderValue::from_str(&clear_cookie)
        .map_err(|e| AppError::internal(format!("invalid clear cookie header: {e}")))?;

    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert(header::SET_COOKIE, cookie_val);
    Ok(res)
}

pub async fn me(
    State(state): State<AppState>,
    AuthenticatedActor(actor): AuthenticatedActor,
) -> Result<Json<MeResponse>, AppError> {
    let permissions = MePermissions {
        is_admin: actor.is_admin(),
        can_manage: actor.can_manage(),
        can_operate: actor.can_operate(),
        can_view_confidential_notes: actor.can_view_confidential_notes(),
    };

    match actor.principal {
        AuthPrincipal::Session { user_id, role, .. } => {
            let user = sqlx::query_as::<_, UserRecord>(
                r#"
                SELECT
                    id,
                    email,
                    full_name,
                    password_hash,
                    role,
                    is_active,
                    last_login_at,
                    created_at
                FROM public.users
                WHERE id = $1 AND is_active = TRUE
                "#,
            )
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::unauthorized("Invalid or inactive session."))?;

            Ok(Json(MeResponse {
                auth_type: "session",
                effective_role: role.as_str().to_string(),
                permissions,
                user: Some(UserResponse::try_from(user)?),
                api_key: None,
            }))
        }
        AuthPrincipal::ApiKey {
            api_key_id,
            role_scope,
            ..
        } => {
            let api_key = sqlx::query_as::<_, ApiKeyRecord>(
                r#"
                SELECT
                    k.id,
                    k.name,
                    k.key_prefix,
                    k.key_hash,
                    k.role_scope,
                    k.created_by,
                    k.last_used_at,
                    k.expires_at,
                    k.revoked_at,
                    k.created_at
                FROM public.api_keys k
                JOIN public.users u ON u.id = k.created_by
                WHERE k.id = $1
                  AND k.revoked_at IS NULL
                  AND (k.expires_at IS NULL OR k.expires_at > pg_catalog.now())
                  AND u.is_active = TRUE
                "#,
            )
            .bind(api_key_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::unauthorized("Invalid, expired, or revoked API key."))?;

            Ok(Json(MeResponse {
                auth_type: "api_key",
                effective_role: role_scope.as_str().to_string(),
                permissions,
                user: None,
                api_key: Some(ApiKeyResponse::try_from(api_key)?),
            }))
        }
    }
}
