use axum::http::header::{HeaderValue, CONTENT_TYPE, RETRY_AFTER};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

const NOSNIFF_HEADER: &str = "x-content-type-options";
const NOSNIFF_VALUE: &str = "nosniff";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request [{code}]: {message}")]
    BadRequest { code: String, message: String },

    #[error("validation error [{code}]: {message}")]
    Validation {
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },

    #[error("conflict [{code}]: {message}")]
    Conflict {
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },

    #[error("idempotency key payload mismatch: {message}")]
    IdempotencyMismatch { message: String },

    #[error("unauthorized: {message}")]
    Unauthorized { message: String },

    #[error("forbidden: {message}")]
    Forbidden { message: String },

    #[error("not found [{code}]: {message}")]
    NotFound { code: String, message: String },

    #[error("method not allowed: {message}")]
    MethodNotAllowed { message: String },

    #[error("payload too large: {message}")]
    PayloadTooLarge { message: String },

    #[error("unsupported media type: {message}")]
    UnsupportedMediaType { message: String },

    #[error("too many requests: {message}")]
    TooManyRequests {
        message: String,
        retry_after_secs: u64,
    },

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal server error: {message}")]
    Internal { message: String },
}

impl AppError {
    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn validation(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn validation_with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self::Validation {
            code: code.into(),
            message: message.into(),
            details: Some(details),
        }
    }

    pub fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Conflict {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn idempotency_mismatch(message: impl Into<String>) -> Self {
        Self::IdempotencyMismatch {
            message: message.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    pub fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::NotFound {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::MethodNotAllowed {
            message: message.into(),
        }
    }

    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::PayloadTooLarge {
            message: message.into(),
        }
    }

    pub fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::UnsupportedMediaType {
            message: message.into(),
        }
    }

    pub fn too_many_requests(message: impl Into<String>, retry_after_secs: u64) -> Self {
        Self::TooManyRequests {
            message: message.into(),
            retry_after_secs: retry_after_secs.max(1),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    pub fn to_error_payload(&self) -> (StatusCode, String, String, Option<serde_json::Value>) {
        match self {
            Self::BadRequest { code, message } => {
                (StatusCode::BAD_REQUEST, code.clone(), message.clone(), None)
            }

            Self::Validation {
                code,
                message,
                details,
            } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                code.clone(),
                message.clone(),
                details.clone(),
            ),

            Self::Conflict {
                code,
                message,
                details,
            } => (
                StatusCode::CONFLICT,
                code.clone(),
                message.clone(),
                details.clone(),
            ),

            Self::IdempotencyMismatch { message } => (
                StatusCode::CONFLICT,
                "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH".to_string(),
                message.clone(),
                None,
            ),

            Self::Unauthorized { message } => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED".to_string(),
                message.clone(),
                None,
            ),

            Self::Forbidden { message } => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN".to_string(),
                message.clone(),
                None,
            ),

            Self::NotFound { code, message } => {
                (StatusCode::NOT_FOUND, code.clone(), message.clone(), None)
            }

            Self::MethodNotAllowed { message } => (
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED".to_string(),
                message.clone(),
                None,
            ),

            Self::PayloadTooLarge { message } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE".to_string(),
                message.clone(),
                None,
            ),

            Self::UnsupportedMediaType { message } => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE".to_string(),
                message.clone(),
                None,
            ),

            Self::TooManyRequests { message, .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED".to_string(),
                message.clone(),
                None,
            ),

            Self::Database(err) => map_database_error(err),

            Self::Internal { message } => {
                tracing::error!("internal error: {}", message);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR".to_string(),
                    "An unexpected error occurred.".to_string(),
                    None,
                )
            }
        }
    }
}

fn map_p0403_error(
    msg: &str,
    detail: Option<&str>,
) -> (StatusCode, String, String, Option<serde_json::Value>) {
    if msg.starts_with("APPEND_ONLY_VIOLATION") {
        (
            StatusCode::FORBIDDEN,
            "APPEND_ONLY_VIOLATION".to_string(),
            "Historical ledger and audit records are immutable.".to_string(),
            None,
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            msg.to_string(),
            detail.unwrap_or(msg).to_string(),
            None,
        )
    }
}

fn map_pg_code(
    code: &str,
    msg: &str,
    detail: Option<&str>,
) -> (StatusCode, String, String, Option<serde_json::Value>) {
    match code {
        // custom postgres error codes from record_stock_movement and record_audit_event
        "P0409" => (
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH".to_string(),
            detail
                .unwrap_or("Idempotency key was already used with a different request payload.")
                .to_string(),
            None,
        ),
        "P0422" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            msg.to_string(),
            detail.unwrap_or(msg).to_string(),
            None,
        ),
        "P0403" => map_p0403_error(msg, detail),
        "P0404" => (
            StatusCode::NOT_FOUND,
            msg.to_string(),
            detail.unwrap_or("Resource not found.").to_string(),
            None,
        ),
        // standard postgres error codes
        "23505" => (
            StatusCode::CONFLICT,
            "DUPLICATE_RESOURCE".to_string(),
            "A resource with these unique attributes already exists.".to_string(),
            None,
        ),
        "23503" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "FOREIGN_KEY_VIOLATION".to_string(),
            "Referenced entity does not exist.".to_string(),
            None,
        ),
        "23514" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "CONSTRAINT_VIOLATION".to_string(),
            "Request violated a database data constraint.".to_string(),
            None,
        ),
        "22003" => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "NUMERIC_OUT_OF_RANGE".to_string(),
            "Numeric value is outside the allowed range.".to_string(),
            None,
        ),
        _ => {
            tracing::error!("unhandled postgres error [{code}]: {msg}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR".to_string(),
                "An unexpected database error occurred.".to_string(),
                None,
            )
        }
    }
}

fn map_database_error(
    err: &sqlx::Error,
) -> (StatusCode, String, String, Option<serde_json::Value>) {
    if let sqlx::Error::Database(db_err) = err {
        let code = db_err.code().unwrap_or_default();
        let detail = db_err
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .and_then(|p| p.detail());

        map_pg_code(code.as_ref(), db_err.message(), detail)
    } else if matches!(err, sqlx::Error::RowNotFound) {
        (
            StatusCode::NOT_FOUND,
            "NOT_FOUND".to_string(),
            "Requested resource was not found.".to_string(),
            None,
        )
    } else {
        tracing::error!("database error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_ERROR".to_string(),
            "Database service is temporarily unavailable.".to_string(),
            None,
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry_after = match &self {
            Self::TooManyRequests {
                retry_after_secs, ..
            } => Some((*retry_after_secs).max(1)),
            _ => None,
        };
        let (status, code, message, details) = self.to_error_payload();

        let envelope = ErrorEnvelope {
            error: ErrorDetail {
                code,
                message,
                details,
            },
        };

        let body = serde_json::to_string(&envelope).unwrap_or_else(|_| {
            json!({
                "error": {
                    "code": "SERIALIZATION_ERROR",
                    "message": "Failed to serialize error response"
                }
            })
            .to_string()
        });

        let mut res = Response::new(body.into());
        *res.status_mut() = status;

        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        res.headers_mut()
            .insert(NOSNIFF_HEADER, HeaderValue::from_static(NOSNIFF_VALUE));
        if let Some(secs) = retry_after {
            if let Ok(val) = HeaderValue::from_str(&secs.to_string()) {
                res.headers_mut().insert(RETRY_AFTER, val);
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_status_and_envelope() {
        let err = AppError::validation("INVALID_SKU", "SKU cannot be empty");
        let (status, code, msg, details) = err.to_error_payload();

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "INVALID_SKU");
        assert_eq!(msg, "SKU cannot be empty");
        assert!(details.is_none());
    }

    #[test]
    fn conflict_error_status_and_envelope() {
        let err = AppError::conflict("SKU_ALREADY_EXISTS", "SKU already exists in catalog");
        let (status, code, msg, _) = err.to_error_payload();

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(code, "SKU_ALREADY_EXISTS");
        assert_eq!(msg, "SKU already exists in catalog");
    }

    #[test]
    fn idempotency_mismatch_status_and_envelope() {
        let err = AppError::idempotency_mismatch("Payload hash mismatch");
        let (status, code, msg, _) = err.to_error_payload();

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(code, "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH");
        assert_eq!(msg, "Payload hash mismatch");
    }

    #[test]
    fn unauthorized_and_forbidden_status() {
        let (status_401, code_401, _, _) =
            AppError::unauthorized("Session expired").to_error_payload();
        assert_eq!(status_401, StatusCode::UNAUTHORIZED);
        assert_eq!(code_401, "UNAUTHORIZED");

        let (status_403, code_403, _, _) =
            AppError::forbidden("Admin role required").to_error_payload();
        assert_eq!(status_403, StatusCode::FORBIDDEN);
        assert_eq!(code_403, "FORBIDDEN");
    }

    #[test]
    fn into_response_has_proper_headers_and_body() {
        let err = AppError::validation("FIELD_REQUIRED", "name is required");
        let resp = err.into_response();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        assert_eq!(resp.headers().get(NOSNIFF_HEADER).unwrap(), NOSNIFF_VALUE);
    }

    #[test]
    fn append_only_p0403_strips_internal_table_names() {
        let (status, code, msg, _) = map_p0403_error(
            "APPEND_ONLY_VIOLATION: table public.stock_ledger is immutable and does not allow DELETE",
            None,
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "APPEND_ONLY_VIOLATION");
        assert!(!msg.contains("stock_ledger"));
        assert!(!msg.contains("public."));
    }

    #[test]
    fn bad_request_status_and_envelope() {
        let err = AppError::bad_request("INVALID_REQUEST", "logout requires a session cookie");
        let (status, code, msg, details) = err.to_error_payload();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "INVALID_REQUEST");
        assert_eq!(msg, "logout requires a session cookie");
        assert!(details.is_none());
    }

    #[test]
    fn too_many_requests_sets_429_and_retry_after_header() {
        let err = AppError::too_many_requests("Too many login attempts.", 42);
        let (status, code, msg, _) = err.to_error_payload();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(code, "RATE_LIMITED");
        assert_eq!(msg, "Too many login attempts.");

        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(RETRY_AFTER).unwrap(), "42");
        assert_eq!(resp.headers().get(NOSNIFF_HEADER).unwrap(), NOSNIFF_VALUE);

        let clamped = AppError::too_many_requests("Slow down.", 0).into_response();
        assert_eq!(clamped.headers().get(RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn pg_constraint_and_numeric_error_codes_map_to_422() {
        let (st_check, code_check, _, _) = map_pg_code("23514", "check constraint", None);
        assert_eq!(st_check, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code_check, "CONSTRAINT_VIOLATION");

        let (st_num, code_num, _, _) = map_pg_code("22003", "numeric field overflow", None);
        assert_eq!(st_num, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code_num, "NUMERIC_OUT_OF_RANGE");

        let (st_idem, code_idem, _, _) = map_pg_code("P0409", "mismatch", None);
        assert_eq!(st_idem, StatusCode::CONFLICT);
        assert_eq!(code_idem, "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH");

        let (st_dup, code_dup, _, _) = map_pg_code("23505", "duplicate", None);
        assert_eq!(st_dup, StatusCode::CONFLICT);
        assert_eq!(code_dup, "DUPLICATE_RESOURCE");

        let (st_fk, code_fk, _, _) = map_pg_code("23503", "fk violation", None);
        assert_eq!(st_fk, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code_fk, "FOREIGN_KEY_VIOLATION");
    }

    #[test]
    fn method_not_allowed_payload_too_large_and_unsupported_media_type_envelopes() {
        for (err, expected_status, expected_code) in [
            (
                AppError::method_not_allowed("nope"),
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
            ),
            (
                AppError::payload_too_large("too big"),
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
            ),
            (
                AppError::unsupported_media_type("need json"),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
            ),
        ] {
            let res = err.into_response();
            assert_eq!(res.status(), expected_status);
            assert_eq!(
                res.headers().get(CONTENT_TYPE).unwrap(),
                "application/json; charset=utf-8"
            );
            assert_eq!(res.headers().get(NOSNIFF_HEADER).unwrap(), NOSNIFF_VALUE);

            let (status, code, _, _) = match expected_code {
                "METHOD_NOT_ALLOWED" => AppError::method_not_allowed("nope").to_error_payload(),
                "PAYLOAD_TOO_LARGE" => AppError::payload_too_large("too big").to_error_payload(),
                _ => AppError::unsupported_media_type("need json").to_error_payload(),
            };
            assert_eq!(status, expected_status);
            assert_eq!(code, expected_code);
        }
    }
}
