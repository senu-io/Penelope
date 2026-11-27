mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use chrono::{Duration, Utc};
use penelope_backend::{routes, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn rbac_matrix_enforces_admin_and_audit_route_boundaries() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let pw = "rbac_matrix_pass_2026!";

    let (admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, pw).await;
    let (_mgr_id, mgr_email) = common::seed_user(&app_pool, "manager", true, pw).await;
    let (_op_id, op_email) = common::seed_user(&app_pool, "operator", true, pw).await;

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));

    let admin_cookie = common::login_cookie(&app, &admin_email, pw).await;
    let mgr_cookie = common::login_cookie(&app, &mgr_email, pw).await;
    let op_cookie = common::login_cookie(&app, &op_email, pw).await;

    let (_mgr_key_id, mgr_key) = common::seed_api_key(&app_pool, admin_id, "manager").await;
    let (_op_key_id, op_key) = common::seed_api_key(&app_pool, admin_id, "operator").await;
    let (_ro_key_id, ro_key) = common::seed_api_key(&app_pool, admin_id, "readonly").await;

    for path in [
        "/api/v1/admin/users",
        "/api/v1/admin/api-keys",
        "/api/v1/audit-logs",
    ] {
        let res = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    for path in [
        "/api/v1/admin/users",
        "/api/v1/admin/api-keys",
        "/api/v1/audit-logs",
        "/api/v1/audit-logs?entity_type=auth",
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "admin failed on {path}");
    }

    for (auth_header, auth_val) in [
        (header::COOKIE.as_str(), mgr_cookie.as_str()),
        ("x-api-key", mgr_key.as_str()),
    ] {
        for forbidden in [
            "/api/v1/admin/users",
            "/api/v1/admin/api-keys",
            "/api/v1/audit-logs?entity_type=auth",
        ] {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(forbidden)
                        .header(auth_header, auth_val)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
        }

        for allowed in [
            "/api/v1/audit-logs",
            "/api/v1/audit-logs?entity_type=category",
        ] {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(allowed)
                        .header(auth_header, auth_val)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }
    }

    for (auth_header, auth_val) in [
        (header::COOKIE.as_str(), op_cookie.as_str()),
        ("x-api-key", op_key.as_str()),
        ("x-api-key", ro_key.as_str()),
    ] {
        for path in [
            "/api/v1/admin/users",
            "/api/v1/admin/api-keys",
            "/api/v1/audit-logs",
        ] {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(auth_header, auth_val)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::FORBIDDEN);
        }
    }
}

#[tokio::test]
async fn api_key_lifecycle_revocation_expiration_and_owner_deactivation() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let pw = "api_key_lifecycle_2026!";
    let (admin_id, admin_email) = common::seed_user(&app_pool, "admin", true, pw).await;
    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));
    let admin_cookie = common::login_cookie(&app, &admin_email, pw).await;

    let bad_scope = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/api-keys")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "name": "Bad Admin Key", "role_scope": "admin" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_scope.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let past_exp = Utc::now() - Duration::minutes(10);
    let bad_exp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/api-keys")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Past Key",
                        "role_scope": "operator",
                        "expires_at": past_exp
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_exp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let create_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/api-keys")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Dock Handheld 07",
                        "role_scope": "operator",
                        "expires_at": Utc::now() + Duration::days(30)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let created_json = common::json_body(create_res).await;
    let raw_key = created_json["raw_key"].as_str().unwrap().to_string();
    let key_id = created_json["api_key"]["id"].as_str().unwrap().to_string();
    assert!(raw_key.starts_with("pen_live_"));
    assert_eq!(raw_key.len(), 73);
    assert_eq!(created_json["api_key"]["key_prefix"], &raw_key[..17]);

    let create_audit: Value = sqlx::query_scalar(
        "SELECT details FROM public.audit_logs WHERE entity_type = 'api_key' AND entity_id = $1 AND action = 'api_key.create'",
    )
    .bind(&key_id)
    .fetch_one(&app_pool)
    .await
    .expect("api_key.create audit row");
    assert!(!create_audit.to_string().contains(&raw_key));

    let list_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/api-keys")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_text = serde_json::to_string(&common::json_body(list_res).await).unwrap();
    assert!(!list_text.contains(&raw_key));
    assert!(!list_text.contains("key_hash"));

    let me_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", &raw_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_res.status(), StatusCode::OK);

    let last_used: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_used_at FROM public.api_keys WHERE id = $1::uuid")
            .bind(&key_id)
            .fetch_one(&app_pool)
            .await
            .unwrap();
    assert!(last_used.is_some());

    let bad_uuid_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/admin/api-keys/not-a-uuid")
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_uuid_res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        common::json_body(bad_uuid_res).await["error"]["code"],
        "INVALID_PATH_PARAM"
    );

    let revoke_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/admin/api-keys/{key_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);
    assert!(common::json_body(revoke_res).await["revoked_at"].is_string());

    let revoke_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE entity_type = 'api_key' AND entity_id = $1 AND action = 'api_key.revoke'",
    )
    .bind(&key_id)
    .fetch_one(&app_pool)
    .await
    .unwrap();
    assert_eq!(revoke_audit_count, 1);

    let double_revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/admin/api-keys/{key_id}"))
                .header(header::COOKIE, &admin_cookie)
                .header(header::ORIGIN, "http://localhost:5173")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(double_revoke.status(), StatusCode::CONFLICT);

    let revoked_use = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", &raw_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked_use.status(), StatusCode::UNAUTHORIZED);

    let (exp_id, exp_raw) = common::seed_api_key(&app_pool, admin_id, "readonly").await;
    sqlx::query(
        "UPDATE public.api_keys SET expires_at = now() - interval '1 minute' WHERE id = $1",
    )
    .bind(exp_id)
    .execute(&app_pool)
    .await
    .unwrap();
    let exp_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", &exp_raw)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp_res.status(), StatusCode::UNAUTHORIZED);

    let (deact_owner_id, _) = common::seed_user(&app_pool, "admin", true, pw).await;
    let (_owner_key_id, owner_raw) =
        common::seed_api_key(&app_pool, deact_owner_id, "operator").await;
    sqlx::query("UPDATE public.users SET is_active = FALSE WHERE id = $1")
        .bind(deact_owner_id)
        .execute(&app_pool)
        .await
        .unwrap();
    let inactive_owner_res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", &owner_raw)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inactive_owner_res.status(), StatusCode::UNAUTHORIZED);
}
