use crate::config;
use crate::crypto;
use crate::error::AppError;
use crate::guards::{AppJson, AppPath, RequireAdmin};
use crate::models::{ApiKeyRecord, ApiKeyResponse, ApiKeyScope, Role, UserRecord, UserResponse};
use crate::services::{AuditEventInput, AuditService};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct UsersListResponse {
    pub items: Vec<UserResponse>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiKeysListResponse {
    pub items: Vec<ApiKeyResponse>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: ApiKeyResponse,
    pub raw_key: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub full_name: String,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub full_name: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub role_scope: String,
    pub expires_at: Option<DateTime<Utc>>,
}

fn normalize_and_validate_email(raw: &str) -> Result<String, AppError> {
    config::normalize_and_validate_email(raw)
        .map_err(|msg| AppError::validation("INVALID_EMAIL", msg))
}

fn validate_full_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    let len = trimmed.chars().count();
    if len == 0 || len > 120 {
        return Err(AppError::validation(
            "INVALID_FULL_NAME",
            "Full name must be between 1 and 120 characters.",
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_password(raw: &str) -> Result<SecretString, AppError> {
    if raw.trim().is_empty() {
        return Err(AppError::validation(
            "WEAK_PASSWORD",
            "Password cannot be blank.",
        ));
    }
    if raw.chars().count() < 12 {
        return Err(AppError::validation(
            "WEAK_PASSWORD",
            "Password must be at least 12 characters long.",
        ));
    }
    if raw.len() > 256 {
        return Err(AppError::validation(
            "PASSWORD_TOO_LONG",
            "Password cannot exceed 256 bytes.",
        ));
    }
    Ok(SecretString::new(raw.to_string()))
}

fn validate_api_key_name(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    let len = trimmed.chars().count();
    if len == 0 || len > 100 {
        return Err(AppError::validation(
            "INVALID_API_KEY_NAME",
            "API key name must be between 1 and 100 characters.",
        ));
    }
    Ok(trimmed.to_string())
}

fn check_admin_update_invariants(
    acting_admin_id: Uuid,
    target_id: Uuid,
    target_role: &str,
    target_active: bool,
    next_role: &str,
    next_active: bool,
    active_admin_count: usize,
) -> Result<(), AppError> {
    if target_id == acting_admin_id && !next_active {
        return Err(AppError::conflict(
            "CANNOT_DEACTIVATE_SELF",
            "Administrators cannot deactivate their own active account.",
        ));
    }

    if target_id == acting_admin_id && next_role != "admin" {
        return Err(AppError::conflict(
            "CANNOT_DEMOTE_SELF",
            "Administrators cannot demote their own admin role.",
        ));
    }

    let removing_active_admin =
        target_role == "admin" && target_active && (next_role != "admin" || !next_active);
    if removing_active_admin && active_admin_count <= 1 {
        return Err(AppError::conflict(
            "LAST_ACTIVE_ADMIN",
            "Cannot deactivate or demote the last remaining active administrator.",
        ));
    }

    Ok(())
}

pub async fn list_users(
    State(state): State<AppState>,
    RequireAdmin(_actor): RequireAdmin,
) -> Result<Json<UsersListResponse>, AppError> {
    let records = sqlx::query_as::<_, UserRecord>(
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
        ORDER BY created_at ASC, id ASC
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let items: Vec<UserResponse> = records
        .into_iter()
        .map(UserResponse::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let total = items.len();

    Ok(Json(UsersListResponse { items, total }))
}

pub async fn create_user(
    State(state): State<AppState>,
    RequireAdmin(actor): RequireAdmin,
    AppJson(payload): AppJson<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let acting_admin_id = actor
        .audit_user_id()
        .ok_or_else(|| AppError::forbidden("Admin session required."))?;

    let email = normalize_and_validate_email(&payload.email)?;
    let full_name = validate_full_name(&payload.full_name)?;
    let role = Role::from_str(&payload.role)?;
    let password = validate_password(&payload.password)?;

    let pw_clone = password.clone();
    let password_hash = tokio::task::spawn_blocking(move || crypto::hash_password(&pw_clone))
        .await
        .map_err(|e| AppError::internal(format!("password hash task failed: {e}")))?
        .map_err(|e| AppError::internal(format!("failed to hash password: {e}")))?;

    let user_id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;

    let created = sqlx::query_as::<_, UserRecord>(
        r#"
        INSERT INTO public.users (id, email, full_name, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, $5, TRUE)
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
    .bind(user_id)
    .bind(&email)
    .bind(&full_name)
    .bind(&password_hash)
    .bind(role.as_str())
    .fetch_one(&mut *tx)
    .await?;

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(acting_admin_id),
            actor_api_key_id: None,
            actor_label: actor.actor_label(),
            action: "user.create".to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(user_id.to_string()),
            ip_address: actor.ip_address,
            details: json!({
                "email": email,
                "full_name": full_name,
                "role": role.as_str()
            }),
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(UserResponse::try_from(created)?)))
}

pub async fn update_user(
    State(state): State<AppState>,
    RequireAdmin(actor): RequireAdmin,
    AppPath(target_id): AppPath<Uuid>,
    AppJson(payload): AppJson<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let acting_admin_id = actor
        .audit_user_id()
        .ok_or_else(|| AppError::forbidden("Admin session required."))?;

    if payload.full_name.is_none()
        && payload.role.is_none()
        && payload.is_active.is_none()
        && payload.password.is_none()
    {
        return Err(AppError::validation(
            "EMPTY_UPDATE",
            "At least one field must be provided when updating a user.",
        ));
    }

    let next_full_name_opt = payload
        .full_name
        .as_deref()
        .map(validate_full_name)
        .transpose()?;
    let next_role_opt = payload.role.as_deref().map(Role::from_str).transpose()?;
    let next_password_hash_opt = match payload.password.as_deref() {
        Some(raw_pw) => {
            let pw = validate_password(raw_pw)?;
            let hash = tokio::task::spawn_blocking(move || crypto::hash_password(&pw))
                .await
                .map_err(|e| AppError::internal(format!("password hash task failed: {e}")))?
                .map_err(|e| AppError::internal(format!("failed to hash password: {e}")))?;
            Some(hash)
        }
        None => None,
    };

    let mut tx = state.db.begin().await?;

    // lock active admins consistently so concurrent updates cannot leave zero admins
    let active_admins: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM public.users WHERE role = 'admin' AND is_active = TRUE ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await?;

    let target = sqlx::query_as::<_, UserRecord>(
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
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(target_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::not_found("USER_NOT_FOUND", "User not found."))?;

    let next_full_name = next_full_name_opt.unwrap_or_else(|| target.full_name.clone());
    let next_role = next_role_opt
        .map(|r| r.as_str().to_string())
        .unwrap_or_else(|| target.role.clone());
    let next_active = payload.is_active.unwrap_or(target.is_active);
    let password_reset = next_password_hash_opt.is_some();

    check_admin_update_invariants(
        acting_admin_id,
        target.id,
        &target.role,
        target.is_active,
        &next_role,
        next_active,
        active_admins.len(),
    )?;

    let mut changed_fields: Vec<&'static str> = Vec::new();
    if next_full_name != target.full_name {
        changed_fields.push("full_name");
    }
    if next_role != target.role {
        changed_fields.push("role");
    }
    if next_active != target.is_active {
        changed_fields.push("is_active");
    }
    if password_reset {
        changed_fields.push("password");
    }

    if changed_fields.is_empty() {
        tx.rollback().await?;
        return Ok(Json(UserResponse::try_from(target)?));
    }

    let next_password_hash = next_password_hash_opt.unwrap_or(target.password_hash);

    let updated = sqlx::query_as::<_, UserRecord>(
        r#"
        UPDATE public.users
        SET
            full_name = $2,
            role = $3,
            is_active = $4,
            password_hash = $5
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
    .bind(target.id)
    .bind(&next_full_name)
    .bind(&next_role)
    .bind(next_active)
    .bind(&next_password_hash)
    .fetch_one(&mut *tx)
    .await?;

    // terminate all active sessions immediately when deactivating or resetting password
    let sessions_revoked = if !next_active || password_reset {
        sqlx::query("DELETE FROM public.sessions WHERE user_id = $1")
            .bind(target.id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    } else {
        0
    };

    let audit_action = if target.is_active && !next_active {
        "user.deactivate"
    } else if !target.is_active && next_active {
        "user.reactivate"
    } else {
        "user.update"
    };

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(acting_admin_id),
            actor_api_key_id: None,
            actor_label: actor.actor_label(),
            action: audit_action.to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(updated.id.to_string()),
            ip_address: actor.ip_address,
            details: json!({
                "email": updated.email,
                "role": updated.role,
                "is_active": updated.is_active,
                "changed_fields": changed_fields,
                "sessions_revoked": sessions_revoked
            }),
        },
    )
    .await?;

    tx.commit().await?;

    Ok(Json(UserResponse::try_from(updated)?))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    RequireAdmin(_actor): RequireAdmin,
) -> Result<Json<ApiKeysListResponse>, AppError> {
    let records = sqlx::query_as::<_, ApiKeyRecord>(
        r#"
        SELECT
            id,
            name,
            key_prefix,
            key_hash,
            role_scope,
            created_by,
            last_used_at,
            expires_at,
            revoked_at,
            created_at
        FROM public.api_keys
        ORDER BY created_at DESC, id DESC
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let items: Vec<ApiKeyResponse> = records
        .into_iter()
        .map(ApiKeyResponse::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let total = items.len();

    Ok(Json(ApiKeysListResponse { items, total }))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    RequireAdmin(actor): RequireAdmin,
    AppJson(payload): AppJson<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), AppError> {
    let acting_admin_id = actor
        .audit_user_id()
        .ok_or_else(|| AppError::forbidden("Admin session required."))?;

    let name = validate_api_key_name(&payload.name)?;
    let role_scope = ApiKeyScope::from_str(&payload.role_scope)?;

    if let Some(exp) = payload.expires_at {
        if exp <= Utc::now() {
            return Err(AppError::validation(
                "INVALID_EXPIRATION",
                "API key expiration timestamp must be in the future.",
            ));
        }
    }

    let (raw_key, key_hash) = crypto::generate_api_key();
    let key_prefix = raw_key[..17].to_string();
    let key_id = Uuid::new_v4();

    let mut tx = state.db.begin().await?;

    let created = sqlx::query_as::<_, ApiKeyRecord>(
        r#"
        INSERT INTO public.api_keys (id, name, key_prefix, key_hash, role_scope, created_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING
            id,
            name,
            key_prefix,
            key_hash,
            role_scope,
            created_by,
            last_used_at,
            expires_at,
            revoked_at,
            created_at
        "#,
    )
    .bind(key_id)
    .bind(&name)
    .bind(&key_prefix)
    .bind(&key_hash)
    .bind(role_scope.as_str())
    .bind(acting_admin_id)
    .bind(payload.expires_at)
    .fetch_one(&mut *tx)
    .await?;

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(acting_admin_id),
            actor_api_key_id: None,
            actor_label: actor.actor_label(),
            action: "api_key.create".to_string(),
            entity_type: "api_key".to_string(),
            entity_id: Some(key_id.to_string()),
            ip_address: actor.ip_address,
            details: json!({
                "name": name,
                "key_prefix": key_prefix,
                "role_scope": role_scope.as_str(),
                "expires_at": payload.expires_at
            }),
        },
    )
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            api_key: ApiKeyResponse::try_from(created)?,
            raw_key,
        }),
    ))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    RequireAdmin(actor): RequireAdmin,
    AppPath(key_id): AppPath<Uuid>,
) -> Result<Json<ApiKeyResponse>, AppError> {
    let acting_admin_id = actor
        .audit_user_id()
        .ok_or_else(|| AppError::forbidden("Admin session required."))?;

    let mut tx = state.db.begin().await?;

    let existing = sqlx::query_as::<_, ApiKeyRecord>(
        r#"
        SELECT
            id,
            name,
            key_prefix,
            key_hash,
            role_scope,
            created_by,
            last_used_at,
            expires_at,
            revoked_at,
            created_at
        FROM public.api_keys
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(key_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::not_found("API_KEY_NOT_FOUND", "API key not found."))?;

    if existing.revoked_at.is_some() {
        return Err(AppError::conflict(
            "API_KEY_ALREADY_REVOKED",
            "API key has already been revoked.",
        ));
    }

    let revoked = sqlx::query_as::<_, ApiKeyRecord>(
        r#"
        UPDATE public.api_keys
        SET revoked_at = pg_catalog.now()
        WHERE id = $1
        RETURNING
            id,
            name,
            key_prefix,
            key_hash,
            role_scope,
            created_by,
            last_used_at,
            expires_at,
            revoked_at,
            created_at
        "#,
    )
    .bind(key_id)
    .fetch_one(&mut *tx)
    .await?;

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(acting_admin_id),
            actor_api_key_id: None,
            actor_label: actor.actor_label(),
            action: "api_key.revoke".to_string(),
            entity_type: "api_key".to_string(),
            entity_id: Some(key_id.to_string()),
            ip_address: actor.ip_address,
            details: json!({
                "name": revoked.name,
                "key_prefix": revoked.key_prefix,
                "role_scope": revoked.role_scope
            }),
        },
    )
    .await?;

    tx.commit().await?;

    Ok(Json(ApiKeyResponse::try_from(revoked)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_invariants_block_self_lockout_and_last_admin_removal() {
        let admin_a = Uuid::new_v4();
        let admin_b = Uuid::new_v4();

        let self_deact =
            check_admin_update_invariants(admin_a, admin_a, "admin", true, "admin", false, 2)
                .unwrap_err();
        let (_, code_deact, _, _) = self_deact.to_error_payload();
        assert_eq!(code_deact, "CANNOT_DEACTIVATE_SELF");

        let self_demote =
            check_admin_update_invariants(admin_a, admin_a, "admin", true, "manager", true, 2)
                .unwrap_err();
        let (_, code_demote, _, _) = self_demote.to_error_payload();
        assert_eq!(code_demote, "CANNOT_DEMOTE_SELF");

        let last_admin =
            check_admin_update_invariants(admin_a, admin_b, "admin", true, "admin", false, 1)
                .unwrap_err();
        let (_, code_last, _, _) = last_admin.to_error_payload();
        assert_eq!(code_last, "LAST_ACTIVE_ADMIN");

        assert!(
            check_admin_update_invariants(admin_a, admin_b, "admin", true, "manager", true, 2)
                .is_ok()
        );
    }

    #[test]
    fn password_and_email_validation_rules() {
        assert_eq!(
            normalize_and_validate_email("  Lead.User@Penelope.Local ").unwrap(),
            "lead.user@penelope.local"
        );
        assert!(normalize_and_validate_email("not_an_email").is_err());
        assert!(normalize_and_validate_email("user@invalid").is_err());
        assert!(normalize_and_validate_email("user@bad..domain").is_err());
        assert!(normalize_and_validate_email("user@penelope.local\x00").is_err());

        let (_, weak_code, _, _) = validate_password("short_8ch")
            .unwrap_err()
            .to_error_payload();
        assert_eq!(weak_code, "WEAK_PASSWORD");
        let (_, long_code, _, _) = validate_password(&"x".repeat(257))
            .unwrap_err()
            .to_error_payload();
        assert_eq!(long_code, "PASSWORD_TOO_LONG");
        assert!(validate_password("valid_12_chars").is_ok());
    }
}
