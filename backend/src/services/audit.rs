use crate::error::AppError;
use crate::models::{AuditLogRecord, AuditLogResponse};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

pub const DEFAULT_AUDIT_LIMIT: i64 = 50;
pub const MAX_AUDIT_LIMIT: i64 = 200;

pub const ALL_ENTITY_TYPES: [&str; 8] = [
    "auth",
    "user",
    "api_key",
    "category",
    "product",
    "stock_ledger",
    "data_io",
    "system",
];

pub const OPERATIONAL_ENTITY_TYPES: [&str; 4] = ["category", "product", "stock_ledger", "data_io"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVisibilityScope {
    Full,
    Operational,
}

#[derive(Debug, Clone)]
pub struct AuditEventInput {
    pub actor_user_id: Option<Uuid>,
    pub actor_api_key_id: Option<Uuid>,
    pub actor_label: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub ip_address: String,
    pub details: Value,
}

#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
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

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogPage {
    pub items: Vec<AuditLogResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
struct NormalizedAuditFilter {
    entity_type: Option<String>,
    entity_id: Option<String>,
    action: Option<String>,
    actor_user_id: Option<Uuid>,
    actor_api_key_id: Option<Uuid>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: i64,
    offset: i64,
}

fn validate_and_normalize_filter(
    scope: AuditVisibilityScope,
    filter: &AuditLogFilter,
) -> Result<NormalizedAuditFilter, AppError> {
    let limit = match filter.limit {
        Some(n) if n <= 0 => {
            return Err(AppError::validation(
                "INVALID_LIMIT",
                "limit must be at least 1.",
            ));
        }
        Some(n) => n.min(MAX_AUDIT_LIMIT),
        None => DEFAULT_AUDIT_LIMIT,
    };

    let offset = match filter.offset {
        Some(n) if n < 0 => {
            return Err(AppError::validation(
                "INVALID_OFFSET",
                "offset cannot be negative.",
            ));
        }
        Some(n) => n,
        None => 0,
    };

    if let (Some(from), Some(to)) = (filter.from, filter.to) {
        if from > to {
            return Err(AppError::validation(
                "INVALID_DATE_RANGE",
                "from timestamp cannot be later than to timestamp.",
            ));
        }
    }

    let entity_type = filter
        .entity_type
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(ref et) = entity_type {
        if !ALL_ENTITY_TYPES.contains(&et.as_str()) {
            return Err(AppError::validation(
                "INVALID_ENTITY_TYPE",
                format!("Unsupported entity_type '{et}'."),
            ));
        }
        if scope == AuditVisibilityScope::Operational
            && !OPERATIONAL_ENTITY_TYPES.contains(&et.as_str())
        {
            return Err(AppError::forbidden(
                "Manager role can only view operational audit events.",
            ));
        }
    }

    let entity_id = filter
        .entity_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let action = filter
        .action
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    Ok(NormalizedAuditFilter {
        entity_type,
        entity_id,
        action,
        actor_user_id: filter.actor_user_id,
        actor_api_key_id: filter.actor_api_key_id,
        from: filter.from,
        to: filter.to,
        limit,
        offset,
    })
}

fn apply_audit_where_clauses<'a>(
    qb: &mut QueryBuilder<'a, Postgres>,
    scope: AuditVisibilityScope,
    filter: &'a NormalizedAuditFilter,
) {
    qb.push(" WHERE 1=1");

    if scope == AuditVisibilityScope::Operational {
        qb.push(" AND entity_type IN ('category', 'product', 'stock_ledger', 'data_io')");
    }

    if let Some(ref et) = filter.entity_type {
        qb.push(" AND entity_type = ");
        qb.push_bind(et);
    }
    if let Some(ref eid) = filter.entity_id {
        qb.push(" AND entity_id = ");
        qb.push_bind(eid);
    }
    if let Some(ref act) = filter.action {
        qb.push(" AND action = ");
        qb.push_bind(act);
    }
    if let Some(uid) = filter.actor_user_id {
        qb.push(" AND actor_user_id = ");
        qb.push_bind(uid);
    }
    if let Some(kid) = filter.actor_api_key_id {
        qb.push(" AND actor_api_key_id = ");
        qb.push_bind(kid);
    }
    if let Some(from) = filter.from {
        qb.push(" AND created_at >= ");
        qb.push_bind(from);
    }
    if let Some(to) = filter.to {
        qb.push(" AND created_at <= ");
        qb.push_bind(to);
    }
}

pub struct AuditService;

impl AuditService {
    // record an audit row inside the caller's database transaction so mutations and audit logs commit together
    pub async fn record_event(
        tx: &mut Transaction<'_, Postgres>,
        input: &AuditEventInput,
    ) -> Result<AuditLogRecord, AppError> {
        if !input.details.is_object() {
            return Err(AppError::validation(
                "INVALID_AUDIT_DETAILS",
                "Audit details must be a JSON object.",
            ));
        }

        let rec = sqlx::query_as::<_, AuditLogRecord>(
            r#"
            SELECT
                id,
                actor_user_id,
                actor_api_key_id,
                actor_label,
                action,
                entity_type,
                entity_id,
                ip_address,
                details,
                created_at
            FROM public.record_audit_event($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(input.actor_user_id)
        .bind(input.actor_api_key_id)
        .bind(&input.actor_label)
        .bind(&input.action)
        .bind(&input.entity_type)
        .bind(&input.entity_id)
        .bind(&input.ip_address)
        .bind(&input.details)
        .fetch_one(&mut **tx)
        .await?;

        Ok(rec)
    }

    // record an audit row directly on the pool (used for unauthenticated auth.login.failure)
    pub async fn record_standalone_event(
        pool: &PgPool,
        input: &AuditEventInput,
    ) -> Result<AuditLogRecord, AppError> {
        if !input.details.is_object() {
            return Err(AppError::validation(
                "INVALID_AUDIT_DETAILS",
                "Audit details must be a JSON object.",
            ));
        }

        let rec = sqlx::query_as::<_, AuditLogRecord>(
            r#"
            SELECT
                id,
                actor_user_id,
                actor_api_key_id,
                actor_label,
                action,
                entity_type,
                entity_id,
                ip_address,
                details,
                created_at
            FROM public.record_audit_event($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(input.actor_user_id)
        .bind(input.actor_api_key_id)
        .bind(&input.actor_label)
        .bind(&input.action)
        .bind(&input.entity_type)
        .bind(&input.entity_id)
        .bind(&input.ip_address)
        .bind(&input.details)
        .fetch_one(pool)
        .await?;

        Ok(rec)
    }

    pub async fn list_events(
        pool: &PgPool,
        scope: AuditVisibilityScope,
        filter: &AuditLogFilter,
    ) -> Result<AuditLogPage, AppError> {
        let norm = validate_and_normalize_filter(scope, filter)?;

        let mut count_qb = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM public.audit_logs");
        apply_audit_where_clauses(&mut count_qb, scope, &norm);
        let total: i64 = count_qb.build_query_scalar().fetch_one(pool).await?;

        let mut data_qb = QueryBuilder::<Postgres>::new(
            r#"
            SELECT
                id,
                actor_user_id,
                actor_api_key_id,
                actor_label,
                action,
                entity_type,
                entity_id,
                ip_address,
                details,
                created_at
            FROM public.audit_logs
            "#,
        );
        apply_audit_where_clauses(&mut data_qb, scope, &norm);
        data_qb.push(" ORDER BY created_at DESC, id DESC LIMIT ");
        data_qb.push_bind(norm.limit);
        data_qb.push(" OFFSET ");
        data_qb.push_bind(norm.offset);

        let records: Vec<AuditLogRecord> = data_qb.build_query_as().fetch_all(pool).await?;
        let items = records.into_iter().map(AuditLogResponse::from).collect();

        Ok(AuditLogPage {
            items,
            total,
            limit: norm.limit,
            offset: norm.offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_validation_defaults_and_clamps_limit() {
        let defaults =
            validate_and_normalize_filter(AuditVisibilityScope::Full, &AuditLogFilter::default())
                .expect("default filter");
        assert_eq!(defaults.limit, DEFAULT_AUDIT_LIMIT);
        assert_eq!(defaults.offset, 0);

        let clamped = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                limit: Some(5000),
                offset: Some(15),
                ..Default::default()
            },
        )
        .expect("clamped filter");
        assert_eq!(clamped.limit, MAX_AUDIT_LIMIT);
        assert_eq!(clamped.offset, 15);
    }

    #[test]
    fn filter_rejects_negative_offset_zero_limit_and_inverted_dates() {
        let zero_limit = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                limit: Some(0),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            zero_limit,
            AppError::Validation { code, .. } if code == "INVALID_LIMIT"
        ));

        let neg_offset = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                offset: Some(-1),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            neg_offset,
            AppError::Validation { code, .. } if code == "INVALID_OFFSET"
        ));

        let now = Utc::now();
        let inverted = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                from: Some(now),
                to: Some(now - chrono::Duration::seconds(10)),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            inverted,
            AppError::Validation { code, .. } if code == "INVALID_DATE_RANGE"
        ));
    }

    #[test]
    fn operational_scope_blocks_security_entity_types_and_allows_operational() {
        for forbidden_entity in ["auth", "user", "api_key", "system"] {
            let err = validate_and_normalize_filter(
                AuditVisibilityScope::Operational,
                &AuditLogFilter {
                    entity_type: Some(forbidden_entity.to_string()),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(
                matches!(err, AppError::Forbidden { .. }),
                "expected forbidden for {forbidden_entity}"
            );
        }

        for allowed_entity in ["category", "product", "stock_ledger", "data_io"] {
            let norm = validate_and_normalize_filter(
                AuditVisibilityScope::Operational,
                &AuditLogFilter {
                    entity_type: Some(format!(" {allowed_entity} ")),
                    ..Default::default()
                },
            )
            .expect("operational entity allowed");
            assert_eq!(norm.entity_type.as_deref(), Some(allowed_entity));
        }
    }

    #[test]
    fn unknown_entity_type_returns_validation_error() {
        let err = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                entity_type: Some("invoices".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AppError::Validation { code, .. } if code == "INVALID_ENTITY_TYPE"
        ));
    }

    #[test]
    fn action_is_lowercased_and_entity_id_is_trimmed() {
        let norm = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                action: Some("  CATEGORY.CREATE  ".to_string()),
                entity_id: Some("  sku-42  ".to_string()),
                ..Default::default()
            },
        )
        .expect("normalized filter");
        assert_eq!(norm.action.as_deref(), Some("category.create"));
        assert_eq!(norm.entity_id.as_deref(), Some("sku-42"));

        let blank_eid = validate_and_normalize_filter(
            AuditVisibilityScope::Full,
            &AuditLogFilter {
                entity_id: Some("   ".to_string()),
                ..Default::default()
            },
        )
        .expect("blank entity_id stripped");
        assert!(blank_eid.entity_id.is_none());
    }
}
