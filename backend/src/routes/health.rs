// liveness and database readiness probes

use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct LiveResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

pub async fn live() -> (StatusCode, Json<LiveResponse>) {
    (
        StatusCode::OK,
        Json(LiveResponse {
            status: "ok",
            version: crate::crate_version(),
        }),
    )
}

pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                database: "ok",
            }),
        ),
        Err(err) => {
            tracing::warn!("readiness database check failed: {}", err);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "unavailable",
                    database: "error",
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::AppConfig;
    use crate::routes::build_router;
    use crate::state::AppState;
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use sqlx::postgres::PgConnectOptions;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn dummy_config() -> AppConfig {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        AppConfig::from_pairs([
            (
                "DATABASE_URL",
                "postgres://penelope_app:penelope_app_password@localhost:5432/penelope_db"
                    .to_string(),
            ),
            ("SESSION_SECRET", key_hex.to_string()),
            ("PENELOPE_ACTIVE_KEY_ID", "1".to_string()),
            ("PENELOPE_ENCRYPTION_KEYS", format!("1:{key_hex}")),
        ])
        .expect("valid test config")
    }

    #[tokio::test]
    async fn health_live_returns_ok_without_db_connection() {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5432)
            .username("penelope_app")
            .database("penelope_db");
        let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy_with(opts);
        let state = AppState::new(pool, Arc::new(dummy_config()));
        let app = build_router(state);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router response");

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );

        let body = to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["version"], crate::crate_version());
    }
}
