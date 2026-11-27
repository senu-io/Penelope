use crate::error::AppError;
use crate::guards::{AppQuery, RequireManager};
use crate::services::{AuditLogFilter, AuditLogPage, AuditService};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AuditLogsQuery {
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub action: Option<String>,
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_audit_logs(
    State(state): State<AppState>,
    RequireManager(actor): RequireManager,
    AppQuery(query): AppQuery<AuditLogsQuery>,
) -> Result<Json<AuditLogPage>, AppError> {
    let scope = actor
        .audit_visibility_scope()
        .ok_or_else(|| AppError::forbidden("Manager or Admin permissions required."))?;

    let filter = AuditLogFilter {
        entity_type: query.entity_type,
        entity_id: query.entity_id,
        action: query.action,
        actor_user_id: query.actor_user_id,
        actor_api_key_id: query.actor_api_key_id,
        from: query.from,
        to: query.to,
        limit: query.limit,
        offset: query.offset,
    };

    let page = AuditService::list_events(&state.db, scope, &filter).await?;
    Ok(Json(page))
}
