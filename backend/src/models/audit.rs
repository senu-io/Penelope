use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub actor_label: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub ip_address: String,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogResponse {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub actor_label: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub ip_address: String,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

impl From<AuditLogRecord> for AuditLogResponse {
    fn from(record: AuditLogRecord) -> Self {
        Self {
            id: record.id,
            actor_user_id: record.actor_user_id,
            actor_api_key_id: record.actor_api_key_id,
            actor_label: record.actor_label,
            action: record.action,
            entity_type: record.entity_type,
            entity_id: record.entity_id,
            ip_address: record.ip_address,
            details: record.details,
            created_at: record.created_at,
        }
    }
}
