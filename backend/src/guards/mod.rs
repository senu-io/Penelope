pub mod auth;
pub mod csrf;
pub mod extractors;
pub mod rate_limit;
pub mod rbac;
pub mod security_headers;

pub use auth::{
    build_clear_session_cookie, build_session_cookie, extract_session_cookie, ActorContext,
    AuthPrincipal, API_KEY_HEADER_NAME, SESSION_COOKIE_NAME,
};
pub use csrf::{verify_cookie_csrf, verify_login_origin};
pub use extractors::{AppJson, AppPath, AppQuery};
pub use rate_limit::{
    classify_rate_limit_group, client_ip_from_extensions, rate_limit_middleware, ClientIp,
    RateLimitGroup, RateLimiterState,
};
pub use rbac::{AuthenticatedActor, RequireAdmin, RequireManager, RequireOperator, RequireSession};
pub use security_headers::{apply_security_headers, build_cors_layer, security_headers_middleware};
