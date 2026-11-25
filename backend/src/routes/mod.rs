// base api router under /api/v1

pub mod health;

use crate::state::AppState;
use axum::http::{header, HeaderValue};
use axum::routing::get;
use axum::Router;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

pub fn build_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready));

    Router::new()
        .nest("/api/v1", api_v1)
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
