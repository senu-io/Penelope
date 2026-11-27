mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use penelope_backend::crypto;
use penelope_backend::guards::security_headers::HSTS_POLICY;
use penelope_backend::guards::SESSION_COOKIE_NAME;
use penelope_backend::{routes, AppState};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn login_sets_httponly_cookie_updates_last_login_and_records_audit() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let (user_id, email) =
        common::seed_user(&app_pool, "manager", true, "warehouse_pass_2026!").await;

    let app_http = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));

    let login_res = app_http
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::USER_AGENT, "PenelopeIntegrationTest/1.0")
                .body(Body::from(
                    json!({
                        "email": format!("  {}  ", email.to_ascii_uppercase()),
                        "password": "warehouse_pass_2026!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("login response");

    assert_eq!(login_res.status(), StatusCode::OK);
    assert_eq!(
        login_res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(login_res
        .headers()
        .get(header::STRICT_TRANSPORT_SECURITY)
        .is_none());

    let set_cookie = login_res
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Path=/"));
    assert!(set_cookie.contains("Max-Age=604800"));
    assert!(!set_cookie.contains("Secure"));

    let login_json = common::json_body(login_res).await;
    assert_eq!(login_json["email"], email);
    assert_eq!(login_json["role"], "manager");
    assert!(login_json.get("password_hash").is_none());
    assert!(login_json["last_login_at"].is_string());

    // db idle expiry remains ~24h even though browser cookie carries the 7d absolute max-age
    let session_row = sqlx::query(
        "SELECT id, last_active_at, expires_at, created_at FROM public.sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("fetch created session");
    let created_at: DateTime<Utc> = session_row.get("created_at");
    let initial_expiry: DateTime<Utc> = session_row.get("expires_at");
    let idle_delta_hours = (initial_expiry - created_at).num_hours();
    assert!((23..=25).contains(&idle_delta_hours));

    let cookie_pair = common::extract_cookie_pair(&set_cookie);

    let me_res = app_http
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("me response");
    assert_eq!(me_res.status(), StatusCode::OK);
    let me_json = common::json_body(me_res).await;
    assert_eq!(me_json["auth_type"], "session");
    assert_eq!(me_json["effective_role"], "manager");
    assert_eq!(me_json["permissions"]["is_admin"], false);
    assert_eq!(me_json["permissions"]["can_manage"], true);
    assert_eq!(me_json["permissions"]["can_operate"], true);
    assert_eq!(me_json["permissions"]["can_view_confidential_notes"], true);
    assert_eq!(me_json["user"]["id"], user_id.to_string());

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE actor_user_id = $1 AND action = 'auth.login.success'",
    )
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .expect("count login success audit");
    assert_eq!(audit_count, 1);

    // backdate last_active_at > 60s to trigger sliding expiry extension
    let session_id: Uuid = session_row.get("id");
    let stale_touch = Utc::now() - Duration::minutes(3);
    sqlx::query("UPDATE public.sessions SET last_active_at = $2, expires_at = $3 WHERE id = $1")
        .bind(session_id)
        .bind(stale_touch)
        .bind(Utc::now() + Duration::hours(12))
        .execute(&app_pool)
        .await
        .unwrap();

    let slide_res = app_http
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(slide_res.status(), StatusCode::OK);

    let slided =
        sqlx::query("SELECT last_active_at, expires_at FROM public.sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&app_pool)
            .await
            .unwrap();
    assert!(slided.get::<DateTime<Utc>, _>("last_active_at") > stale_touch);
    assert!(slided.get::<DateTime<Utc>, _>("expires_at") > Utc::now() + Duration::hours(23));

    // when created 160h ago, sliding extension clamps to the 168h absolute cap
    let old_created = Utc::now() - Duration::hours(160);
    sqlx::query("UPDATE public.sessions SET created_at = $2, last_active_at = $3, expires_at = $4 WHERE id = $1")
        .bind(session_id)
        .bind(old_created)
        .bind(stale_touch)
        .bind(Utc::now() + Duration::hours(4))
        .execute(&app_pool)
        .await
        .unwrap();

    let clamped_res = app_http
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clamped_res.status(), StatusCode::OK);
    let clamped_expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM public.sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&app_pool)
            .await
            .unwrap();
    assert!(clamped_expiry <= old_created + Duration::hours(168));

    // when COOKIE_SECURE=true, responses emit Secure cookie + HSTS
    let app_https = routes::build_router(AppState::new(
        app_pool,
        Arc::new(common::test_app_config(true)),
    ));
    let secure_res = app_https
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": "warehouse_pass_2026!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("https login response");
    assert_eq!(secure_res.status(), StatusCode::OK);
    assert_eq!(
        secure_res
            .headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .unwrap(),
        HSTS_POLICY
    );
    let secure_cookie = secure_res
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(secure_cookie.contains("; Secure"));
}

#[tokio::test]
async fn login_failure_input_bounds_and_extractor_json_envelopes() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let (_active_id, active_email) =
        common::seed_user(&app_pool, "operator", true, "correct_op_pass_2026!").await;
    let (_inactive_id, inactive_email) =
        common::seed_user(&app_pool, "operator", false, "inactive_op_pass_2026!").await;

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));

    let unknown_email = format!("nobody_{}@penelope.local", Uuid::new_v4().simple());

    for (target_email, attempted_pw, expected_reason) in [
        (
            active_email.as_str(),
            "wrong_password_attempt",
            "invalid_password",
        ),
        (
            unknown_email.as_str(),
            "some_random_password",
            "user_not_found",
        ),
        (
            inactive_email.as_str(),
            "inactive_op_pass_2026!",
            "user_inactive",
        ),
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "email": target_email,
                            "password": attempted_pw
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("login failure response");

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let err_json = common::json_body(res).await;
        assert_eq!(err_json["error"]["code"], "UNAUTHORIZED");

        let row = sqlx::query(
            r#"
            SELECT actor_user_id, details
            FROM public.audit_logs
            WHERE action = 'auth.login.failure'
              AND details->>'email' = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(target_email)
        .fetch_one(&app_pool)
        .await
        .expect("fetch login failure audit row");

        assert!(row.get::<Option<Uuid>, _>("actor_user_id").is_none());
        let details: Value = row.get("details");
        assert_eq!(details["reason"], expected_reason);
        assert!(!details.to_string().contains(attempted_pw));
    }

    // blank credentials and oversized login inputs reject before argon2id or audit writes
    let oversized_email = format!("{}@penelope.local", "a".repeat(250));
    for (bad_email, bad_pw) in [
        ("", "some_password"),
        (active_email.as_str(), ""),
        (active_email.as_str(), &"p".repeat(257)),
        (oversized_email.as_str(), "some_password"),
    ] {
        let bad_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "email": bad_email, "password": bad_pw }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            common::json_body(bad_res).await["error"]["code"],
            "INVALID_LOGIN_INPUT"
        );
    }

    let oversized_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE action = 'auth.login.failure' AND details->>'email' = $1",
    )
    .bind(&oversized_email)
    .fetch_one(&app_pool)
    .await
    .unwrap();
    assert_eq!(oversized_audit_count, 0);

    // disallowed or duplicate Origin header on login fails 403
    let evil_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::from(
                    json!({
                        "email": active_email,
                        "password": "correct_op_pass_2026!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evil_login.status(), StatusCode::FORBIDDEN);

    let dup_origin_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::from(
                    json!({
                        "email": active_email,
                        "password": "correct_op_pass_2026!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_origin_login.status(), StatusCode::FORBIDDEN);

    // malformed json, missing fields, wrong media type, unknown route, wrong method -> json ErrorEnvelope
    let bad_json = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{broken"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_json.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        common::json_body(bad_json).await["error"]["code"],
        "INVALID_JSON"
    );

    let missing_field = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "email": active_email }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_field.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        common::json_body(missing_field).await["error"]["code"],
        "INVALID_REQUEST_PAYLOAD"
    );

    let wrong_ct = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_ct.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        common::json_body(wrong_ct).await["error"]["code"],
        "UNSUPPORTED_MEDIA_TYPE"
    );

    let unknown_route = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_route.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        common::json_body(unknown_route).await["error"]["code"],
        "ROUTE_NOT_FOUND"
    );

    let wrong_method = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        common::json_body(wrong_method).await["error"]["code"],
        "METHOD_NOT_ALLOWED"
    );
}

#[tokio::test]
async fn logout_deletes_session_clears_cookie_and_blocks_reuse() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let (user_id, email) =
        common::seed_user(&app_pool, "admin", true, "admin_logout_pass_2026!").await;

    let app = routes::build_router(AppState::new(
        app_pool.clone(),
        Arc::new(common::test_app_config(false)),
    ));

    let cookie_pair = common::login_cookie(&app, &email, "admin_logout_pass_2026!").await;

    let no_origin_logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_origin_logout.status(), StatusCode::FORBIDDEN);

    // referer fallback also satisfies csrf when Origin is absent
    let logout_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(header::COOKIE, &cookie_pair)
                .header(header::REFERER, "http://localhost:5173/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);
    let cleared_cookie = logout_res
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cleared_cookie.contains("Max-Age=0"));

    let reuse_res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reuse_res.status(), StatusCode::UNAUTHORIZED);

    let logout_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public.audit_logs WHERE actor_user_id = $1 AND action = 'auth.logout'",
    )
    .bind(user_id)
    .fetch_one(&app_pool)
    .await
    .unwrap();
    assert_eq!(logout_audit_count, 1);
}

#[tokio::test]
async fn expired_idle_and_absolute_sessions_and_deactivated_users_are_rejected() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let cfg = common::test_app_config(false);
    let (user_id, _) = common::seed_user(&app_pool, "operator", true, "ttl_test_pass_2026!").await;
    let app = routes::build_router(AppState::new(app_pool.clone(), Arc::new(cfg.clone())));

    let (idle_raw, idle_hash) =
        crypto::generate_session_token(&cfg.session_secret).expect("idle token");
    let idle_sid = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO public.sessions (id, user_id, token_hash, ip_address, user_agent, last_active_at, expires_at, created_at)
        VALUES ($1, $2, $3, '127.0.0.1', 'test', $4, $5, $4)
        "#,
    )
    .bind(idle_sid)
    .bind(user_id)
    .bind(&idle_hash)
    .bind(now - Duration::hours(25))
    .bind(now - Duration::minutes(1))
    .execute(&app_pool)
    .await
    .unwrap();

    let idle_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE_NAME}={idle_raw}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(idle_res.status(), StatusCode::UNAUTHORIZED);
    let idle_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public.sessions WHERE id = $1")
        .bind(idle_sid)
        .fetch_one(&app_pool)
        .await
        .unwrap();
    assert_eq!(idle_left, 0);

    // past 168h absolute limit even with a future expires_at must reject and clean up the row
    let (abs_raw, abs_hash) =
        crypto::generate_session_token(&cfg.session_secret).expect("abs token");
    let abs_sid = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO public.sessions (id, user_id, token_hash, ip_address, user_agent, last_active_at, expires_at, created_at)
        VALUES ($1, $2, $3, '127.0.0.1', 'test', $4, $5, $6)
        "#,
    )
    .bind(abs_sid)
    .bind(user_id)
    .bind(&abs_hash)
    .bind(now - Duration::minutes(5))
    .bind(now + Duration::hours(12))
    .bind(now - Duration::hours(169))
    .execute(&app_pool)
    .await
    .unwrap();

    let abs_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE_NAME}={abs_raw}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(abs_res.status(), StatusCode::UNAUTHORIZED);
    let abs_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public.sessions WHERE id = $1")
        .bind(abs_sid)
        .fetch_one(&app_pool)
        .await
        .unwrap();
    assert_eq!(abs_left, 0);

    let (live_raw, live_hash) =
        crypto::generate_session_token(&cfg.session_secret).expect("live token");
    sqlx::query(
        r#"
        INSERT INTO public.sessions (id, user_id, token_hash, ip_address, user_agent, last_active_at, expires_at, created_at)
        VALUES ($1, $2, $3, '127.0.0.1', 'test', $4, $5, $4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&live_hash)
    .bind(now)
    .bind(now + Duration::hours(24))
    .execute(&app_pool)
    .await
    .unwrap();

    sqlx::query("UPDATE public.users SET is_active = FALSE WHERE id = $1")
        .bind(user_id)
        .execute(&app_pool)
        .await
        .unwrap();

    let deact_res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::COOKIE, format!("{SESSION_COOKIE_NAME}={live_raw}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deact_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_me_supports_api_key_logout_rejects_api_key_and_invalid_key_never_falls_back_to_cookie(
) {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let cfg = common::test_app_config(false);
    let (owner_id, email) =
        common::seed_user(&app_pool, "admin", true, "api_owner_pass_2026!").await;
    let app = routes::build_router(AppState::new(app_pool.clone(), Arc::new(cfg)));

    let (key_id, raw_key) = common::seed_api_key(&app_pool, owner_id, "readonly").await;

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
    let me_json = common::json_body(me_res).await;
    assert_eq!(me_json["auth_type"], "api_key");
    assert_eq!(me_json["effective_role"], "readonly");
    assert_eq!(me_json["permissions"]["is_admin"], false);
    assert_eq!(me_json["permissions"]["can_manage"], false);
    assert_eq!(me_json["permissions"]["can_operate"], false);
    assert_eq!(me_json["api_key"]["id"], key_id.to_string());
    assert!(me_json["api_key"].get("key_hash").is_none());

    let key_logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header("x-api-key", &raw_key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(key_logout.status(), StatusCode::FORBIDDEN);

    let cookie_pair = common::login_cookie(&app, &email, "api_owner_pass_2026!").await;

    // invalid or duplicate x-api-key must fail 401 and never fall back to the valid session cookie
    let (unknown_key, _) = crypto::generate_api_key();
    let fallback_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", unknown_key)
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fallback_attempt.status(), StatusCode::UNAUTHORIZED);

    let dup_key_attempt = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header("x-api-key", &raw_key)
                .header("x-api-key", &raw_key)
                .header(header::COOKIE, cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_key_attempt.status(), StatusCode::UNAUTHORIZED);
}
