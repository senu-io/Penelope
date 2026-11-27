pub mod admin;
pub mod audit;
pub mod auth;
pub mod health;

use crate::error::AppError;
use crate::guards::{build_cors_layer, rate_limit_middleware, security_headers_middleware};
use crate::state::AppState;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use tower_http::trace::TraceLayer;

const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub fn build_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/audit-logs", get(audit::list_audit_logs))
        .route(
            "/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route("/admin/users/:id", patch(admin::update_user))
        .route(
            "/admin/api-keys",
            get(admin::list_api_keys).post(admin::create_api_key),
        )
        .route("/admin/api-keys/:id", delete(admin::revoke_api_key));

    Router::new()
        .nest("/api/v1", api_v1)
        .fallback(|| async { AppError::not_found("ROUTE_NOT_FOUND", "Endpoint not found.") })
        .method_not_allowed_fallback(|| async {
            AppError::method_not_allowed("HTTP method is not allowed for this endpoint.")
        })
        .layer(from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(DefaultBodyLimit::max(DEFAULT_MAX_BODY_BYTES))
        .layer(build_cors_layer(&state.config.cors_allowed_origins))
        .layer(from_fn_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
