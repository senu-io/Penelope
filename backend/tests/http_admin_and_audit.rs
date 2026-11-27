mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use penelope_backend::{routes, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn admin_user_create_validation_duplicate_and_list() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let pw = "admin_create_pass_2026!";
    let (_admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, pw).await;
    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));
    let admin_cookie = common::login_cookie(&app, &admin_email, pw).await;

    let weak_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": format!("weak_{}@penelope.local", Uuid::new_v4().simple()),
                        "full_name": "Weak User",
                        "password": "short_pw",
                        "role": "operator"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(weak_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        common::json_body(weak_res).await["error"]["code"],
        "WEAK_PASSWORD"
    );

    let raw_email = format!("New.Op_{}@Penelope.Local", Uuid::new_v4().simple());
    let lower_email = raw_email.to_ascii_lowercase();
    let op_pw = "operator_strong_pass_2026!";
    let create_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": raw_email,
                        "full_name": "Floor Lead",
                        "password": op_pw,
                        "role": "operator"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let created_json = common::json_body(create_res).await;
    let created_id = created_json["id"].as_str().unwrap().to_string();
    assert_eq!(created_json["email"], lower_email);
    assert_eq!(created_json["role"], "operator");
    assert!(created_json.get("password_hash").is_none());

    let create_audit: Value = sqlx::query_scalar(
        "SELECT details FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1 AND action = 'user.create'",
    )
    .bind(&created_id)
    .fetch_one(&app_pool)
    .await
    .expect("user.create audit row");
    assert!(!create_audit.to_string().contains(op_pw));

    let dup_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": lower_email,
                        "full_name": "Duplicate User",
                        "password": op_pw,
                        "role": "operator"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_res.status(), StatusCode::CONFLICT);
    assert_eq!(
        common::json_body(dup_res).await["error"]["code"],
        "DUPLICATE_RESOURCE"
    );

    let _op_cookie = common::login_cookie(&app, &lower_email, op_pw).await;
    let list_res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_json = common::json_body(list_res).await;
    let list_str = serde_json::to_string(&list_json).unwrap();
    assert!(list_str.contains(&lower_email));
    assert!(!list_str.contains("password_hash"));
}

#[tokio::test]
async fn admin_patch_enforces_empty_check_self_lockout_noop_and_not_found() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let pw = "admin_patch_pass_2026!";
    let (admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, pw).await;
    let (other_id, _) = common::seed_user(&app_pool, "operator", true, pw).await;

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));
    let admin_cookie = common::login_cookie(&app, &admin_email, pw).await;

    let empty_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{other_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        common::json_body(empty_res).await["error"]["code"],
        "EMPTY_UPDATE"
    );

    let missing_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{}", Uuid::new_v4()))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "full_name": "Ghost" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_res.status(), StatusCode::NOT_FOUND);

    let self_deact = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{admin_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "is_active": false }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(self_deact.status(), StatusCode::CONFLICT);
    assert_eq!(
        common::json_body(self_deact).await["error"]["code"],
        "CANNOT_DEACTIVATE_SELF"
    );

    let self_demote = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{admin_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "role": "operator" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(self_demote.status(), StatusCode::CONFLICT);
    assert_eq!(
        common::json_body(self_demote).await["error"]["code"],
        "CANNOT_DEMOTE_SELF"
    );

    let ok_patch = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{other_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "full_name": "Promoted Shift Lead", "role": "manager" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_patch.status(), StatusCode::OK);
    let patched = common::json_body(ok_patch).await;
    assert_eq!(patched["full_name"], "Promoted Shift Lead");
    assert_eq!(patched["role"], "manager");

    // repeating identical values must not append an extra user.update audit row
    let noop_patch = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{other_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "full_name": "Promoted Shift Lead", "role": "manager" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(noop_patch.status(), StatusCode::OK);

    let audit_cnt: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1 AND action = 'user.update'",
    )
    .bind(other_id.to_string())
    .fetch_one(&app_pool)
    .await
    .unwrap();
    assert_eq!(audit_cnt, 1);
}

#[tokio::test]
async fn admin_deactivation_and_password_reset_immediately_revoke_sessions() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let admin_pw = "admin_session_kick_2026!";
    let op_pw = "initial_op_pass_2026!";
    let (_admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, admin_pw).await;
    let (op_id, op_email) = common::seed_user(&app_pool, "operator", true, op_pw).await;

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));
    let admin_cookie = common::login_cookie(&app, &admin_email, admin_pw).await;
    let op_cookie_1 = common::login_cookie(&app, &op_email, op_pw).await;

    let deact_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{op_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "is_active": false }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deact_res.status(), StatusCode::OK);

    let deact_details: Value = sqlx::query_scalar(
        "SELECT details FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1 AND action = 'user.deactivate'",
    )
    .bind(op_id.to_string())
    .fetch_one(&app_pool)
    .await
    .expect("user.deactivate audit row");
    assert!(deact_details["sessions_revoked"].as_u64().unwrap() >= 1);

    let kicked = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &op_cookie_1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(kicked.status(), StatusCode::UNAUTHORIZED);

    let sess_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM public.sessions WHERE user_id = $1")
            .bind(op_id)
            .fetch_one(&app_pool)
            .await
            .unwrap();
    assert_eq!(sess_count, 0);

    let react_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{op_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "is_active": true }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(react_res.status(), StatusCode::OK);

    let react_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1 AND action = 'user.reactivate'",
    )
    .bind(op_id.to_string())
    .fetch_one(&app_pool)
    .await
    .unwrap();
    assert_eq!(react_count, 1);

    let op_cookie_2 = common::login_cookie(&app, &op_email, op_pw).await;

    let new_pw = "brand_new_op_pass_2026!";
    let reset_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/admin/users/{op_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "password": new_pw }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset_res.status(), StatusCode::OK);

    let pw_audit: Value = sqlx::query_scalar(
        "SELECT details FROM public.audit_logs WHERE entity_type = 'user' AND entity_id = $1 AND action = 'user.update'",
    )
    .bind(op_id.to_string())
    .fetch_one(&app_pool)
    .await
    .expect("password reset user.update audit row");
    assert!(pw_audit["sessions_revoked"].as_u64().unwrap() >= 1);
    assert!(!pw_audit.to_string().contains(new_pw));

    let kicked_after_reset = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &op_cookie_2)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(kicked_after_reset.status(), StatusCode::UNAUTHORIZED);

    let old_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "email": op_email, "password": op_pw }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_login.status(), StatusCode::UNAUTHORIZED);

    let _op_cookie_3 = common::login_cookie(&app, &op_email, new_pw).await;
}

#[tokio::test]
async fn audit_logs_endpoint_enforces_admin_vs_manager_visibility_and_filters() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let pw = "audit_scope_pass_2026!";
    let (admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, pw).await;
    let (_mgr_id, mgr_email) = common::seed_user(&app_pool, "manager", true, pw).await;
    let (seeded_actor_id, cat_id) = common::seed_actor_and_category(&app_pool).await;

    let mut tx = app_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT * FROM public.record_audit_event($1, NULL, 'seeded@test', 'user.create', 'user', $2, '127.0.0.1', '{}'::jsonb)",
    )
    .bind(seeded_actor_id)
    .bind(Uuid::new_v4().to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "SELECT * FROM public.record_audit_event($1, NULL, 'seeded@test', 'category.create', 'category', $2, '127.0.0.1', '{}'::jsonb)",
    )
    .bind(seeded_actor_id)
    .bind(cat_id.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));
    let admin_cookie = common::login_cookie(&app, &admin_email, pw).await;
    let mgr_cookie = common::login_cookie(&app, &mgr_email, pw).await;

    let create_key_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/api-keys")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "name": "Audit Manager Key", "role_scope": "manager" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mgr_key = common::json_body(create_key_res).await["raw_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(admin_id, seeded_actor_id);

    let bad_query = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit-logs?limit=abc")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        common::json_body(bad_query).await["error"]["code"],
        "INVALID_QUERY_PARAMS"
    );

    let admin_all = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/audit-logs?actor_user_id={seeded_actor_id}"
                ))
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_all.status(), StatusCode::OK);
    let admin_json = common::json_body(admin_all).await;
    assert_eq!(admin_json["total"], 2);

    let admin_paged = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/audit-logs?actor_user_id={seeded_actor_id}&limit=1&offset=1"
                ))
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let paged_json = common::json_body(admin_paged).await;
    assert_eq!(paged_json["total"], 2);
    assert_eq!(paged_json["items"].as_array().unwrap().len(), 1);

    for (hdr, val) in [
        (header::COOKIE.as_str(), mgr_cookie.as_str()),
        ("x-api-key", mgr_key.as_str()),
    ] {
        let mgr_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/audit-logs?actor_user_id={seeded_actor_id}&entity_id={cat_id}&action=CATEGORY.CREATE"
                    ))
                    .header(hdr, val)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mgr_res.status(), StatusCode::OK);
        let mgr_json = common::json_body(mgr_res).await;
        assert_eq!(mgr_json["total"], 1);
        assert_eq!(mgr_json["items"][0]["action"], "category.create");

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit-logs?entity_type=user")
                    .header(hdr, val)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
}
