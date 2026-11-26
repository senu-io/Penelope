// bounded in-memory token-bucket rate limiter keyed by peer ip

use crate::error::AppError;
use crate::state::AppState;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Extensions, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

const MAX_BUCKETS: usize = 10_000;
const IDLE_EVICT_SECS: u64 = 300;
const PRUNE_EVERY_CHECKS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitGroup {
    Auth,
    Api,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct RateLimiterInner {
    buckets: HashMap<(RateLimitGroup, String), TokenBucket>,
    checks: u64,
}

#[derive(Debug)]
pub struct RateLimiterState {
    auth_per_min: u32,
    api_per_min: u32,
    max_buckets: usize,
    inner: Mutex<RateLimiterInner>,
}

// extract peer ip from ConnectInfo without trusting spoofable forwarded headers
pub fn client_ip_from_extensions(extensions: &Extensions) -> Option<String> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
}

// group auth login/logout separately from general api traffic and keep health probes exempt
pub fn classify_rate_limit_group(method: &Method, path: &str) -> Option<RateLimitGroup> {
    if *method == Method::OPTIONS {
        return None;
    }
    if path == "/api/v1/health/live" || path == "/api/v1/health/ready" {
        return None;
    }
    if *method == Method::POST && (path == "/api/v1/auth/login" || path == "/api/v1/auth/logout") {
        return Some(RateLimitGroup::Auth);
    }
    if path.starts_with("/api/v1/") {
        return Some(RateLimitGroup::Api);
    }
    None
}

impl RateLimiterState {
    pub fn new(auth_per_min: u32, api_per_min: u32) -> Self {
        Self::with_max_buckets(auth_per_min, api_per_min, MAX_BUCKETS)
    }

    pub fn with_max_buckets(auth_per_min: u32, api_per_min: u32, max_buckets: usize) -> Self {
        Self {
            auth_per_min: auth_per_min.max(1),
            api_per_min: api_per_min.max(1),
            max_buckets: max_buckets.max(1),
            inner: Mutex::new(RateLimiterInner {
                buckets: HashMap::new(),
                checks: 0,
            }),
        }
    }

    pub fn check(&self, group: RateLimitGroup, client_ip: &str) -> Result<(), u64> {
        self.check_at(group, client_ip, Instant::now())
    }

    pub fn check_at(
        &self,
        group: RateLimitGroup,
        client_ip: &str,
        now: Instant,
    ) -> Result<(), u64> {
        let capacity = match group {
            RateLimitGroup::Auth => f64::from(self.auth_per_min),
            RateLimitGroup::Api => f64::from(self.api_per_min),
        };
        let refill_per_sec = capacity / 60.0;

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.checks = guard.checks.wrapping_add(1);

        if guard.checks.is_multiple_of(PRUNE_EVERY_CHECKS)
            || guard.buckets.len() >= self.max_buckets
        {
            guard.buckets.retain(|_, b| {
                now.saturating_duration_since(b.last_refill).as_secs() < IDLE_EVICT_SECS
            });
        }

        let key = (group, client_ip.to_string());
        if !guard.buckets.contains_key(&key) && guard.buckets.len() >= self.max_buckets {
            if let Some(oldest_key) = guard
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(k, _)| k.clone())
            {
                guard.buckets.remove(&oldest_key);
            }
        }

        let bucket = guard.buckets.entry(key).or_insert(TokenBucket {
            tokens: capacity,
            last_refill: now,
        });

        let elapsed_secs = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed_secs * refill_per_sec).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - bucket.tokens;
            let wait_secs = (needed / refill_per_sec).ceil().max(1.0) as u64;
            Err(wait_secs)
        }
    }
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(group) = classify_rate_limit_group(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };

    let client_ip =
        client_ip_from_extensions(req.extensions()).unwrap_or_else(|| "unknown-peer".to_string());

    if let Err(retry_after_secs) = state.rate_limiter.check(group, &client_ip) {
        return AppError::too_many_requests(
            "Too many requests. Please slow down and try again later.",
            retry_after_secs,
        )
        .into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use axum::body::Body;
    use axum::http::{header, StatusCode};
    use axum::middleware::from_fn_with_state;
    use axum::routing::{get, post};
    use axum::Router;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_app_state(auth_per_min: u32, api_per_min: u32) -> AppState {
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
            ("RATE_LIMIT_AUTH_PER_MIN", auth_per_min.to_string()),
            ("RATE_LIMIT_API_PER_MIN", api_per_min.to_string()),
        ])
        .expect("valid config");
        let pool = PgPoolOptions::new().connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(5432)
                .username("penelope_app")
                .database("penelope_db"),
        );
        AppState::new(pool, Arc::new(cfg))
    }

    #[test]
    fn classifies_auth_api_and_exempt_routes() {
        assert_eq!(
            classify_rate_limit_group(&Method::POST, "/api/v1/auth/login"),
            Some(RateLimitGroup::Auth)
        );
        assert_eq!(
            classify_rate_limit_group(&Method::POST, "/api/v1/auth/logout"),
            Some(RateLimitGroup::Auth)
        );
        assert_eq!(
            classify_rate_limit_group(&Method::GET, "/api/v1/auth/me"),
            Some(RateLimitGroup::Api)
        );
        assert_eq!(
            classify_rate_limit_group(&Method::GET, "/api/v1/audit-logs"),
            Some(RateLimitGroup::Api)
        );
        assert_eq!(
            classify_rate_limit_group(&Method::GET, "/api/v1/health/live"),
            None
        );
        assert_eq!(
            classify_rate_limit_group(&Method::GET, "/api/v1/health/ready"),
            None
        );
        assert_eq!(
            classify_rate_limit_group(&Method::OPTIONS, "/api/v1/auth/login"),
            None
        );
    }

    #[test]
    fn token_bucket_enforces_limit_refills_and_isolates_ips() {
        let limiter = RateLimiterState::new(3, 60);
        let t0 = Instant::now();

        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t0)
            .is_ok());
        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t0)
            .is_ok());
        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t0)
            .is_ok());

        let err = limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t0)
            .unwrap_err();
        assert_eq!(err, 20);

        // different ip keeps an independent bucket
        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.2", t0)
            .is_ok());

        // after 20s at 3 tokens/min, 1 token refills
        let t1 = t0 + Duration::from_secs(20);
        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t1)
            .is_ok());
        assert!(limiter
            .check_at(RateLimitGroup::Auth, "10.0.0.1", t1)
            .is_err());
    }

    #[test]
    fn token_bucket_respects_max_buckets_cap() {
        let limiter = RateLimiterState::with_max_buckets(10, 10, 3);
        let t0 = Instant::now();

        for i in 0..8 {
            let ip = format!("192.0.2.{i}");
            assert!(limiter
                .check_at(RateLimitGroup::Api, &ip, t0 + Duration::from_millis(i))
                .is_ok());
        }

        let guard = limiter.inner.lock().unwrap();
        assert!(guard.buckets.len() <= 3);
    }

    #[tokio::test]
    async fn rate_limit_middleware_returns_429_with_retry_after_and_exempts_health() {
        let state = test_app_state(2, 5);
        let app = Router::new()
            .route("/api/v1/health/live", get(|| async { StatusCode::OK }))
            .route("/api/v1/auth/login", post(|| async { StatusCode::OK }))
            .route("/api/v1/auth/me", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state.clone(), rate_limit_middleware))
            .with_state(state);

        // two logins allowed, third fails with 429 and Retry-After
        for i in 0..3 {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            if i < 2 {
                assert_eq!(res.status(), StatusCode::OK);
            } else {
                assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
                assert!(res.headers().get(header::RETRY_AFTER).is_some());
            }
        }

        // /auth/me uses separate general api bucket so it is still allowed
        let me_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(me_res.status(), StatusCode::OK);

        // /health/live stays exempt even after many requests
        for _ in 0..5 {
            let live_res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/health/live")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(live_res.status(), StatusCode::OK);
        }
    }
}
