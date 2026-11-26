// postgresql integration tests for AuditService and initial admin bootstrap

mod common;

use chrono::{Duration, Utc};
use penelope_backend::config::InitialAdminConfig;
use penelope_backend::services::{
    bootstrap_initial_admin, AuditEventInput, AuditLogFilter, AuditService, AuditVisibilityScope,
    BootstrapOutcome,
};
use penelope_backend::AppError;
use secrecy::SecretString;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn audit_service_transactional_commit_and_rollback() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let (actor_id, _cat_id) = common::seed_actor_and_category(&app_pool).await;

    // rolled-back transaction must not leave either user or audit entry behind
    let rolled_back_email = format!("rb_{}@penelope.local", Uuid::new_v4().simple());
    let rolled_back_uid = Uuid::new_v4();
    let mut rb_tx = app_pool.begin().await.expect("begin rollback tx");

    sqlx::query(
        "INSERT INTO public.users (id, email, full_name, password_hash, role) VALUES ($1, $2, $3, $4, 'operator')",
    )
    .bind(rolled_back_uid)
    .bind(&rolled_back_email)
    .bind("Rollback User")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g")
    .execute(&mut *rb_tx)
    .await
    .expect("insert user in rollback tx");

    AuditService::record_event(
        &mut rb_tx,
        &AuditEventInput {
            actor_user_id: Some(actor_id),
            actor_api_key_id: None,
            actor_label: "test@penelope.local".to_string(),
            action: "user.create".to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(rolled_back_uid.to_string()),
            ip_address: "127.0.0.1".to_string(),
            details: json!({ "email": rolled_back_email }),
        },
    )
    .await
    .expect("record audit event inside tx");

    rb_tx.rollback().await.expect("rollback tx");

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public.users WHERE id = $1")
        .bind(rolled_back_uid)
        .fetch_one(&app_pool)
        .await
        .expect("count rolled back user");
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM public.audit_logs WHERE entity_id = $1")
            .bind(rolled_back_uid.to_string())
            .fetch_one(&app_pool)
            .await
            .expect("count rolled back audit");
    assert_eq!(user_count, 0);
    assert_eq!(audit_count, 0);

    // committed transaction keeps both rows
    let committed_email = format!("ok_{}@penelope.local", Uuid::new_v4().simple());
    let committed_uid = Uuid::new_v4();
    let mut ok_tx = app_pool.begin().await.expect("begin commit tx");

    sqlx::query(
        "INSERT INTO public.users (id, email, full_name, password_hash, role) VALUES ($1, $2, $3, $4, 'operator')",
    )
    .bind(committed_uid)
    .bind(&committed_email)
    .bind("Committed User")
    .bind("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g")
    .execute(&mut *ok_tx)
    .await
    .expect("insert user in commit tx");

    let recorded = AuditService::record_event(
        &mut ok_tx,
        &AuditEventInput {
            actor_user_id: Some(actor_id),
            actor_api_key_id: None,
            actor_label: "test@penelope.local".to_string(),
            action: "user.create".to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(committed_uid.to_string()),
            ip_address: "127.0.0.1".to_string(),
            details: json!({ "email": committed_email }),
        },
    )
    .await
    .expect("record audit event before commit");

    ok_tx.commit().await.expect("commit tx");

    let committed_audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM public.audit_logs WHERE id = $1")
            .bind(recorded.id)
            .fetch_one(&app_pool)
            .await
            .expect("count committed audit");
    assert_eq!(committed_audit_count, 1);
}

#[tokio::test]
async fn audit_service_standalone_login_failure_and_db_whitelist_rejection() {
    let (_owner_pool, app_pool) = common::setup_pools().await;

    let fail_rec = AuditService::record_standalone_event(
        &app_pool,
        &AuditEventInput {
            actor_user_id: None,
            actor_api_key_id: None,
            actor_label: "anonymous:badlogin@penelope.local".to_string(),
            action: "auth.login.failure".to_string(),
            entity_type: "auth".to_string(),
            entity_id: None,
            ip_address: "10.0.0.14".to_string(),
            details: json!({ "reason": "invalid_credentials" }),
        },
    )
    .await
    .expect("record unauthenticated login failure");
    assert_eq!(fail_rec.action, "auth.login.failure");
    assert!(fail_rec.actor_user_id.is_none());

    // non-object details are rejected in rust before hitting postgres
    let non_obj_err = AuditService::record_standalone_event(
        &app_pool,
        &AuditEventInput {
            actor_user_id: None,
            actor_api_key_id: None,
            actor_label: "anonymous:bad".to_string(),
            action: "auth.login.failure".to_string(),
            entity_type: "auth".to_string(),
            entity_id: None,
            ip_address: "10.0.0.14".to_string(),
            details: json!(["not", "an", "object"]),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        non_obj_err,
        AppError::Validation { code, .. } if code == "INVALID_AUDIT_DETAILS"
    ));

    // direct record_audit_event with stock_ledger entity_type is rejected by db whitelist
    let stock_err = AuditService::record_standalone_event(
        &app_pool,
        &AuditEventInput {
            actor_user_id: None,
            actor_api_key_id: None,
            actor_label: "anonymous:bad".to_string(),
            action: "stock.movement.receive".to_string(),
            entity_type: "stock_ledger".to_string(),
            entity_id: None,
            ip_address: "10.0.0.14".to_string(),
            details: json!({}),
        },
    )
    .await
    .unwrap_err();
    let (status, code, _, _) = stock_err.to_error_payload();
    assert_eq!(status.as_u16(), 422);
    assert_eq!(code, "INVALID_AUDIT_EVENT");
}

#[tokio::test]
async fn audit_service_role_scoped_list_events_and_filters() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let (actor_id, cat_id) = common::seed_actor_and_category(&app_pool).await;

    let api_key_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO public.api_keys (id, name, key_prefix, key_hash, role_scope, created_by)
        VALUES ($1, 'Audit Test Key', 'pen_live_audit01', $2, 'manager', $3)
        "#,
    )
    .bind(api_key_id)
    .bind(format!("{:064x}", Uuid::new_v4().as_u128()))
    .bind(actor_id)
    .execute(&app_pool)
    .await
    .expect("seed audit test api key");

    let mut tx = app_pool.begin().await.expect("begin seed audit tx");
    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(actor_id),
            actor_api_key_id: None,
            actor_label: "manager@penelope.local".to_string(),
            action: "user.create".to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(Uuid::new_v4().to_string()),
            ip_address: "127.0.0.1".to_string(),
            details: json!({ "role": "operator" }),
        },
    )
    .await
    .expect("record user.create event");

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: Some(actor_id),
            actor_api_key_id: None,
            actor_label: "manager@penelope.local".to_string(),
            action: "category.create".to_string(),
            entity_type: "category".to_string(),
            entity_id: Some(cat_id.to_string()),
            ip_address: "127.0.0.1".to_string(),
            details: json!({ "code": "TEST" }),
        },
    )
    .await
    .expect("record category.create event");

    AuditService::record_event(
        &mut tx,
        &AuditEventInput {
            actor_user_id: None,
            actor_api_key_id: Some(api_key_id),
            actor_label: "key:Audit Test Key".to_string(),
            action: "category.update".to_string(),
            entity_type: "category".to_string(),
            entity_id: Some(cat_id.to_string()),
            ip_address: "127.0.0.1".to_string(),
            details: json!({ "name": "Updated" }),
        },
    )
    .await
    .expect("record category.update event from api key");
    tx.commit().await.expect("commit seed audit tx");

    let full_page = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Full,
        &AuditLogFilter {
            actor_user_id: Some(actor_id),
            from: Some(Utc::now() - Duration::minutes(5)),
            to: Some(Utc::now() + Duration::minutes(5)),
            limit: Some(10),
            offset: Some(0),
            ..Default::default()
        },
    )
    .await
    .expect("list full audit events");
    assert_eq!(full_page.total, 2);
    assert_eq!(full_page.items.len(), 2);

    // manager operational scope returns only category.create for that user and excludes user.create
    let op_page = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Operational,
        &AuditLogFilter {
            actor_user_id: Some(actor_id),
            ..Default::default()
        },
    )
    .await
    .expect("list operational audit events");
    assert_eq!(op_page.total, 1);
    assert_eq!(op_page.items.len(), 1);
    assert_eq!(op_page.items[0].entity_type, "category");
    assert_eq!(op_page.items[0].action, "category.create");

    // uppercase action filter and entity_id filter work together
    let by_action_and_eid = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Operational,
        &AuditLogFilter {
            action: Some("CATEGORY.CREATE".to_string()),
            entity_id: Some(cat_id.to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("filter by action and entity_id");
    assert_eq!(by_action_and_eid.total, 1);
    assert_eq!(
        by_action_and_eid.items[0].entity_id.as_deref(),
        Some(cat_id.to_string().as_str())
    );

    // filter by actor_api_key_id isolates api key events
    let by_key = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Operational,
        &AuditLogFilter {
            actor_api_key_id: Some(api_key_id),
            ..Default::default()
        },
    )
    .await
    .expect("filter by api_key_id");
    assert_eq!(by_key.total, 1);
    assert_eq!(by_key.items[0].action, "category.update");
    assert_eq!(by_key.items[0].actor_api_key_id, Some(api_key_id));

    // out-of-range past window returns zero rows
    let past_page = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Full,
        &AuditLogFilter {
            actor_user_id: Some(actor_id),
            to: Some(Utc::now() - Duration::hours(1)),
            ..Default::default()
        },
    )
    .await
    .expect("past date window");
    assert_eq!(past_page.total, 0);
    assert!(past_page.items.is_empty());

    // pagination offset works cleanly
    let paged = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Full,
        &AuditLogFilter {
            actor_user_id: Some(actor_id),
            limit: Some(1),
            offset: Some(1),
            ..Default::default()
        },
    )
    .await
    .expect("paginated query");
    assert_eq!(paged.total, 2);
    assert_eq!(paged.items.len(), 1);

    // manager explicitly filtering by user or auth entity_type is forbidden
    let forbidden_err = AuditService::list_events(
        &app_pool,
        AuditVisibilityScope::Operational,
        &AuditLogFilter {
            entity_type: Some("user".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(forbidden_err, AppError::Forbidden { .. }));
}

#[tokio::test]
async fn bootstrap_initial_admin_disabled_idempotent_and_concurrent_safe() {
    let (_owner_pool, app_pool) = common::setup_pools().await;

    let disabled = bootstrap_initial_admin(&app_pool, None)
        .await
        .expect("disabled bootstrap");
    assert_eq!(disabled, BootstrapOutcome::Disabled);

    let cfg = Arc::new(InitialAdminConfig {
        email: format!("admin_{}@penelope.local", Uuid::new_v4().simple()),
        password: SecretString::new("strong_bootstrap_pass_2026".to_string()),
        full_name: "System Administrator".to_string(),
    });

    // concurrent calls serialize via pg_advisory_xact_lock without errors or duplicate admin rows
    let pool_a = app_pool.clone();
    let pool_b = app_pool.clone();
    let cfg_a = Arc::clone(&cfg);
    let cfg_b = Arc::clone(&cfg);

    let task_a = tokio::spawn(async move { bootstrap_initial_admin(&pool_a, Some(&cfg_a)).await });
    let task_b = tokio::spawn(async move { bootstrap_initial_admin(&pool_b, Some(&cfg_b)).await });

    let res_a = task_a.await.unwrap().expect("concurrent bootstrap a");
    let res_b = task_b.await.unwrap().expect("concurrent bootstrap b");

    let created_count = [res_a, res_b]
        .iter()
        .filter(|r| matches!(r, BootstrapOutcome::CreatedAdmin { .. }))
        .count();
    assert!(created_count <= 1);

    let third = bootstrap_initial_admin(&app_pool, Some(&cfg))
        .await
        .expect("subsequent bootstrap call");
    assert!(matches!(
        third,
        BootstrapOutcome::SkippedExistingUsers { existing_count } if existing_count >= 1
    ));
}

#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn bootstrap_initial_admin_tx_provisioning_hashes_and_audits() {
    use penelope_backend::crypto;
    use penelope_backend::services::insert_bootstrap_admin_in_tx;

    let (_owner_pool, app_pool) = common::setup_pools().await;
    let cfg = InitialAdminConfig {
        email: format!("Admin_{}@Penelope.Local", Uuid::new_v4().simple()),
        password: SecretString::new("strong_bootstrap_pass_2026".to_string()),
        full_name: "System Administrator".to_string(),
    };

    let mut tx = app_pool.begin().await.expect("begin bootstrap tx");
    let (user_id, normalized_email) = insert_bootstrap_admin_in_tx(&mut tx, &cfg)
        .await
        .expect("insert bootstrap admin in tx");
    assert_eq!(normalized_email, cfg.email.to_ascii_lowercase());

    let (stored_role, is_active, stored_hash): (String, bool, String) =
        sqlx::query_as("SELECT role, is_active, password_hash FROM public.users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .expect("fetch bootstrapped admin row");
    assert_eq!(stored_role, "admin");
    assert!(is_active);
    assert!(crypto::verify_password(&cfg.password, &stored_hash).expect("verify argon2 hash"));

    let (actor_label, action): (String, String) = sqlx::query_as(
        "SELECT actor_label, action FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1",
    )
    .bind(user_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("fetch bootstrap audit log");
    assert_eq!(actor_label, "system:bootstrap");
    assert_eq!(action, "user.bootstrap.admin");

    tx.rollback().await.expect("rollback bootstrap test tx");
}
