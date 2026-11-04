// standardized error envelope and status code mappings

use axum::http::header::{HeaderValue, CONTENT_TYPE};
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

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal server error: {message}")]
    Internal { message: String },
}

impl AppError {
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

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    // map AppError to HTTP status code, machine-readable code, and message
    pub fn to_error_payload(&self) -> (StatusCode, String, String, Option<serde_json::Value>) {
        match self {
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

fn map_database_error(
    err: &sqlx::Error,
) -> (StatusCode, String, String, Option<serde_json::Value>) {
    if let sqlx::Error::Database(db_err) = err {
        let code = db_err.code().unwrap_or_default();
        let detail = db_err
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .and_then(|p| p.detail());

        match code.as_ref() {
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
                db_err.message().to_string(),
                detail.unwrap_or(db_err.message()).to_string(),
                None,
            ),
            "P0403" => (
                StatusCode::FORBIDDEN,
                db_err.message().to_string(),
                detail.unwrap_or(db_err.message()).to_string(),
                None,
            ),
            "P0404" => (
                StatusCode::NOT_FOUND,
                db_err.message().to_string(),
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
            _ => {
                tracing::error!("unhandled postgres error [{code}]: {}", db_err.message());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR".to_string(),
                    "An unexpected database error occurred.".to_string(),
                    None,
                )
            }
        }
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
}
