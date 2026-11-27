use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::header::{
    self, HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, RETRY_AFTER,
};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub const CSP_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';";
pub const PERMISSIONS_POLICY: &str = "camera=(self), microphone=(), geolocation=()";
pub const HSTS_POLICY: &str = "max-age=31536000; includeSubDomains";

pub fn apply_security_headers(headers: &mut HeaderMap, include_hsts: bool) {
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CSP_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert_with(|| HeaderValue::from_static("no-store"));

    if include_hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS_POLICY),
        );
    }
}

pub async fn security_headers_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    apply_security_headers(res.headers_mut(), state.config.cookie_secure);
    res
}

pub fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            CONTENT_TYPE,
            ACCEPT,
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("idempotency-key"),
        ])
        .expose_headers([RETRY_AFTER])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::error::AppError;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state(cookie_secure: bool) -> AppState {
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cfg = AppConfig::from_pairs([
            (
                "DATABASE_URL",
                "postgres://penelope_app:penelope_app_password@127.0.0.1:5432/penelope_db"
                    .to_string(),
            ),
            ("SESSION_SECRET", key_hex.to_string()),
            ("PENELOPE_ACTIVE_KEY_ID", "1".to_string()),
            ("PENELOPE_ENCRYPTION_KEYS", format!("1:{key_hex}")),
            (
                "COOKIE_SECURE",
                if cookie_secure { "true" } else { "false" }.to_string(),
            ),
        ])
        .expect("valid test config");
        let pool = PgPoolOptions::new().connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(5432)
                .username("penelope_app")
                .database("penelope_db"),
        );
        AppState::new(pool, Arc::new(cfg))
    }

    #[tokio::test]
    async fn security_headers_attached_to_ok_and_error_responses() {
        let state = test_state(false);
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .route(
                "/unauth",
                get(|| async { AppError::unauthorized("Session missing") }),
            )
            .route(
                "/limited",
                get(|| async { AppError::too_many_requests("Slow down", 15) }),
            )
            .layer(build_cors_layer(&["http://localhost:5173".to_string()]))
            .layer(from_fn_with_state(
                state.clone(),
                security_headers_middleware,
            ))
            .with_state(state);

        for (path, expected_status) in [
            ("/ok", StatusCode::OK),
            ("/unauth", StatusCode::UNAUTHORIZED),
            ("/limited", StatusCode::TOO_MANY_REQUESTS),
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), expected_status);
            assert_eq!(
                res.headers().get("content-security-policy").unwrap(),
                CSP_POLICY
            );
            assert_eq!(
                res.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
                "nosniff"
            );
            assert_eq!(res.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
            assert_eq!(
                res.headers().get("referrer-policy").unwrap(),
                "strict-origin-when-cross-origin"
            );
            assert_eq!(
                res.headers().get("permissions-policy").unwrap(),
                PERMISSIONS_POLICY
            );
            assert_eq!(
                res.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert!(res
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .is_none());
        }

        let https_state = test_state(true);
        let https_app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(
                https_state.clone(),
                security_headers_middleware,
            ))
            .with_state(https_state);
        let https_res = https_app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            https_res
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            HSTS_POLICY
        );
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_blocks_unknown_origin() {
        let state = test_state(false);
        let app = Router::new()
            .route(
                "/api/v1/limited",
                get(|| async { AppError::too_many_requests("Slow down", 12) }),
            )
            .layer(build_cors_layer(&["http://localhost:5173".to_string()]))
            .layer(from_fn_with_state(
                state.clone(),
                security_headers_middleware,
            ))
            .with_state(state);

        let ok_preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/limited")
                    .header(header::ORIGIN, "http://localhost:5173")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type, idempotency-key, x-api-key",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            ok_preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://localhost:5173"
        );
        assert_eq!(
            ok_preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );

        let evil_preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/v1/limited")
                    .header(header::ORIGIN, "https://evil.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(evil_preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());

        let actual_res = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/limited")
                    .header(header::ORIGIN, "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(actual_res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            actual_res
                .headers()
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap(),
            "retry-after"
        );
    }
}
