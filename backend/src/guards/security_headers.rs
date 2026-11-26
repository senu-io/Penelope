// http security headers and explicit-origin cors configuration

use axum::extract::Request;
use axum::http::header::{self, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, RETRY_AFTER};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub const CSP_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';";
pub const PERMISSIONS_POLICY: &str = "camera=(self), microphone=(), geolocation=()";

pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

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
    use crate::error::AppError;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::middleware::from_fn;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[tokio::test]
    async fn security_headers_attached_to_ok_and_error_responses() {
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
            .layer(from_fn(security_headers_middleware));

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
        }
    }

    #[tokio::test]
    async fn cors_allows_configured_origin_and_blocks_unknown_origin() {
        let app = Router::new()
            .route(
                "/api/v1/limited",
                get(|| async { AppError::too_many_requests("Slow down", 12) }),
            )
            .layer(build_cors_layer(&["http://localhost:5173".to_string()]))
            .layer(from_fn(security_headers_middleware));

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
