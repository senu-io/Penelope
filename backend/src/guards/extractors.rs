use crate::error::AppError;
use axum::async_trait;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use serde::de::DeserializeOwned;

pub struct AppJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for AppJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::BytesRejection(rej)) => {
                if rej.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    Err(AppError::payload_too_large(
                        "Request body exceeds the maximum allowed size.",
                    ))
                } else {
                    Err(AppError::bad_request(
                        "INVALID_REQUEST_BODY",
                        "Unable to read request body.",
                    ))
                }
            }
            Err(JsonRejection::MissingJsonContentType(_)) => Err(AppError::unsupported_media_type(
                "Content-Type must be application/json.",
            )),
            Err(JsonRejection::JsonSyntaxError(_)) => Err(AppError::bad_request(
                "INVALID_JSON",
                "Request body is not valid JSON.",
            )),
            Err(JsonRejection::JsonDataError(_)) => Err(AppError::validation(
                "INVALID_REQUEST_PAYLOAD",
                "Request JSON payload has missing or invalid fields.",
            )),
            Err(_) => Err(AppError::bad_request(
                "INVALID_JSON",
                "Invalid JSON request body.",
            )),
        }
    }
}

pub struct AppPath<T>(pub T);

#[async_trait]
impl<S, T> FromRequestParts<S> for AppPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
    Path<T>: FromRequestParts<S, Rejection = PathRejection>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(PathRejection::MissingPathParams(_)) => {
                Err(AppError::internal("missing path parameters"))
            }
            Err(_) => Err(AppError::bad_request(
                "INVALID_PATH_PARAM",
                "Invalid path parameter.",
            )),
        }
    }
}

pub struct AppQuery<T>(pub T);

#[async_trait]
impl<S, T> FromRequestParts<S> for AppQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
    Query<T>: FromRequestParts<S, Rejection = QueryRejection>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(_) => Err(AppError::bad_request(
                "INVALID_QUERY_PARAMS",
                "Invalid query parameters.",
            )),
        }
    }
}
