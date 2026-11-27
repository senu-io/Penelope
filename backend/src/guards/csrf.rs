use crate::config::validate_cors_origin;
use crate::error::AppError;
use axum::http::{header, HeaderMap, Method};

pub fn is_unsafe_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

pub fn extract_origin_from_referer(referer: &str) -> Option<String> {
    let trimmed = referer.trim();
    let (scheme, rest) = if let Some(after) = trimmed.strip_prefix("http://") {
        ("http", after)
    } else if let Some(after) = trimmed.strip_prefix("https://") {
        ("https", after)
    } else if let Some((raw_scheme, after)) = trimmed.split_once("://") {
        let lower = raw_scheme.to_ascii_lowercase();
        if lower == "http" {
            ("http", after)
        } else if lower == "https" {
            ("https", after)
        } else {
            return None;
        }
    } else {
        return None;
    };

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let candidate = format!("{scheme}://{}", &rest[..authority_end]);
    validate_cors_origin(&candidate).ok()
}

pub fn extract_request_origin(headers: &HeaderMap) -> Option<String> {
    let origins: Vec<_> = headers.get_all(header::ORIGIN).iter().collect();
    if origins.len() > 1 {
        return None;
    }

    // when Origin is present, never fall back to Referer
    if let Some(origin_val) = origins.first() {
        let raw = origin_val.to_str().ok()?.trim();
        if raw.eq_ignore_ascii_case("null") || raw.is_empty() {
            return None;
        }
        return validate_cors_origin(raw).ok();
    }

    headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(extract_origin_from_referer)
}

fn origin_is_allowed(origin: &str, allowed_origins: &[String]) -> bool {
    allowed_origins
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(origin))
}

pub fn verify_cookie_csrf(
    method: &Method,
    headers: &HeaderMap,
    allowed_origins: &[String],
) -> Result<(), AppError> {
    if !is_unsafe_method(method) {
        return Ok(());
    }

    let Some(origin) = extract_request_origin(headers) else {
        return Err(AppError::forbidden(
            "Cross-origin or missing Origin header on cookie-authenticated mutation.",
        ));
    };

    if !origin_is_allowed(&origin, allowed_origins) {
        return Err(AppError::forbidden(
            "Origin is not allowed for cookie-authenticated mutations.",
        ));
    }

    Ok(())
}

// non-browser clients without Origin can still log in; browser origins must be in allow-list
pub fn verify_login_origin(
    headers: &HeaderMap,
    allowed_origins: &[String],
) -> Result<(), AppError> {
    let origins: Vec<_> = headers.get_all(header::ORIGIN).iter().collect();
    if origins.is_empty() {
        return Ok(());
    }
    if origins.len() > 1 {
        return Err(AppError::forbidden(
            "Multiple Origin headers are not permitted.",
        ));
    }

    let raw = origins[0]
        .to_str()
        .map_err(|_| AppError::forbidden("Malformed Origin header."))?
        .trim();
    if raw.eq_ignore_ascii_case("null") {
        return Err(AppError::forbidden("Origin 'null' is not permitted."));
    }

    let normalized =
        validate_cors_origin(raw).map_err(|_| AppError::forbidden("Invalid Origin header."))?;
    if !origin_is_allowed(&normalized, allowed_origins) {
        return Err(AppError::forbidden("Origin is not in allow-list."));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec![
            "http://localhost:5173".to_string(),
            "https://wms.example.com".to_string(),
        ]
    }

    #[test]
    fn safe_methods_bypass_csrf_check() {
        let empty = HeaderMap::new();
        assert!(verify_cookie_csrf(&Method::GET, &empty, &allowed()).is_ok());
        assert!(verify_cookie_csrf(&Method::HEAD, &empty, &allowed()).is_ok());
        assert!(verify_cookie_csrf(&Method::OPTIONS, &empty, &allowed()).is_ok());
    }

    #[test]
    fn unsafe_methods_accept_allowed_origin_and_referer_fallback() {
        let mut with_origin = HeaderMap::new();
        with_origin.insert(header::ORIGIN, "HTTP://Localhost:5173".parse().unwrap());
        assert!(verify_cookie_csrf(&Method::POST, &with_origin, &allowed()).is_ok());

        let mut with_referer = HeaderMap::new();
        with_referer.insert(
            header::REFERER,
            "https://wms.example.com/catalog?page=2#row-1"
                .parse()
                .unwrap(),
        );
        assert!(verify_cookie_csrf(&Method::DELETE, &with_referer, &allowed()).is_ok());
    }

    #[test]
    fn unsafe_methods_reject_missing_mismatched_and_null_origin() {
        let missing = HeaderMap::new();
        assert!(verify_cookie_csrf(&Method::POST, &missing, &allowed()).is_err());

        let mut mismatch = HeaderMap::new();
        mismatch.insert(header::ORIGIN, "https://attacker.example".parse().unwrap());
        assert!(verify_cookie_csrf(&Method::PATCH, &mismatch, &allowed()).is_err());

        // "Origin: null" must fail even if a matching Referer is present
        let mut null_with_referer = HeaderMap::new();
        null_with_referer.insert(header::ORIGIN, "null".parse().unwrap());
        null_with_referer.insert(
            header::REFERER,
            "http://localhost:5173/dashboard".parse().unwrap(),
        );
        assert!(verify_cookie_csrf(&Method::POST, &null_with_referer, &allowed()).is_err());
    }

    #[test]
    fn login_origin_allows_absent_or_matching_and_rejects_evil_origin() {
        let absent = HeaderMap::new();
        assert!(verify_login_origin(&absent, &allowed()).is_ok());

        let mut ok_headers = HeaderMap::new();
        ok_headers.insert(header::ORIGIN, "http://localhost:5173".parse().unwrap());
        assert!(verify_login_origin(&ok_headers, &allowed()).is_ok());

        let mut evil_headers = HeaderMap::new();
        evil_headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(verify_login_origin(&evil_headers, &allowed()).is_err());

        let mut null_headers = HeaderMap::new();
        null_headers.insert(header::ORIGIN, "null".parse().unwrap());
        assert!(verify_login_origin(&null_headers, &allowed()).is_err());

        let mut dup_headers = HeaderMap::new();
        dup_headers.append(header::ORIGIN, "http://localhost:5173".parse().unwrap());
        dup_headers.append(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(verify_login_origin(&dup_headers, &allowed()).is_err());
        assert!(verify_cookie_csrf(&Method::POST, &dup_headers, &allowed()).is_err());
    }
}
