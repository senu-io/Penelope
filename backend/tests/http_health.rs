// http health endpoint integration tests against postgres

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use penelope_backend::config::AppConfig;
use penelope_backend::{routes, AppState};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

fn test_app_config() -> AppConfig {
    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    AppConfig::from_pairs([
        (
            "DATABASE_URL",
            "postgres://penelope_app:penelope_app_password@localhost:5432/penelope_db".to_string(),
        ),
        ("SESSION_SECRET", key_hex.to_string()),
        ("PENELOPE_ACTIVE_KEY_ID", "1".to_string()),
        ("PENELOPE_ENCRYPTION_KEYS", format!("1:{key_hex}")),
    ])
    .expect("valid test config")
}

#[tokio::test]
async fn health_live_returns_ok_and_nosniff() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let state = AppState::new(app_pool, Arc::new(test_app_config()));
    let app = routes::build_router(state);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("live probe response");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );

    let body = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read live body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("parse live json");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], penelope_backend::crate_version());
}

#[tokio::test]
async fn health_ready_returns_ok_with_live_postgres() {
    let (_owner_pool, app_pool) = common::setup_pools().await;
    let state = AppState::new(app_pool, Arc::new(test_app_config()));
    let app = routes::build_router(state);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("ready probe response");

    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read ready body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("parse ready json");
    assert_eq!(json["status"], "ready");
    assert_eq!(json["database"], "ok");
}

#[tokio::test]
async fn health_ready_returns_503_when_database_unreachable() {
    let bad_opts = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(1)
        .username("penelope_app")
        .database("penelope_db");
    let bad_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(bad_opts);

    let state = AppState::new(bad_pool, Arc::new(test_app_config()));
    let app = routes::build_router(state);

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("ready failure response");

    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read 503 body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("parse 503 json");
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["database"], "error");
}
