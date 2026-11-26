// server-side role-based access control extractors

use crate::error::AppError;
use crate::guards::auth::ActorContext;
use crate::state::AppState;
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

pub fn authorize_operator(actor: &ActorContext) -> Result<(), AppError> {
    if actor.can_operate() {
        Ok(())
    } else {
        Err(AppError::forbidden(
            "Operator or higher permissions required.",
        ))
    }
}

pub fn authorize_manager(actor: &ActorContext) -> Result<(), AppError> {
    if actor.can_manage() {
        Ok(())
    } else {
        Err(AppError::forbidden(
            "Manager or Admin permissions required.",
        ))
    }
}

pub fn authorize_admin(actor: &ActorContext) -> Result<(), AppError> {
    if actor.is_admin() {
        Ok(())
    } else {
        Err(AppError::forbidden("Admin session required."))
    }
}

pub fn authorize_session(actor: &ActorContext) -> Result<(), AppError> {
    if actor.is_session() {
        Ok(())
    } else {
        Err(AppError::forbidden("Interactive session required."))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedActor(pub ActorContext);

#[derive(Debug, Clone)]
pub struct RequireOperator(pub ActorContext);

#[derive(Debug, Clone)]
pub struct RequireManager(pub ActorContext);

#[derive(Debug, Clone)]
pub struct RequireAdmin(pub ActorContext);

#[derive(Debug, Clone)]
pub struct RequireSession(pub ActorContext);

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedActor {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let actor = ActorContext::from_request_parts(parts, state).await?;
        Ok(Self(actor))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for RequireOperator {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let actor = ActorContext::from_request_parts(parts, state).await?;
        authorize_operator(&actor)?;
        Ok(Self(actor))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for RequireManager {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let actor = ActorContext::from_request_parts(parts, state).await?;
        authorize_manager(&actor)?;
        Ok(Self(actor))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let actor = ActorContext::from_request_parts(parts, state).await?;
        authorize_admin(&actor)?;
        Ok(Self(actor))
    }
}

#[async_trait]
impl FromRequestParts<AppState> for RequireSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let actor = ActorContext::from_request_parts(parts, state).await?;
        authorize_session(&actor)?;
        Ok(Self(actor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guards::auth::AuthPrincipal;
    use crate::models::{ApiKeyScope, Role};
    use crate::services::AuditVisibilityScope;
    use uuid::Uuid;

    fn make_session(role: Role) -> ActorContext {
        ActorContext {
            principal: AuthPrincipal::Session {
                session_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                email: format!("{}@penelope.local", role.as_str()),
                full_name: "Test User".to_string(),
                role,
            },
            ip_address: "127.0.0.1".to_string(),
        }
    }

    fn make_key(role_scope: ApiKeyScope) -> ActorContext {
        ActorContext {
            principal: AuthPrincipal::ApiKey {
                api_key_id: Uuid::new_v4(),
                name: format!("Key {}", role_scope.as_str()),
                key_prefix: "pen_live_00001111".to_string(),
                role_scope,
                created_by: Uuid::new_v4(),
            },
            ip_address: "127.0.0.1".to_string(),
        }
    }

    #[test]
    fn rbac_matrix_matches_all_six_principals() {
        let admin = make_session(Role::Admin);
        let mgr_sess = make_session(Role::Manager);
        let op_sess = make_session(Role::Operator);
        let mgr_key = make_key(ApiKeyScope::Manager);
        let op_key = make_key(ApiKeyScope::Operator);
        let ro_key = make_key(ApiKeyScope::Readonly);

        // admin check: admin session only
        assert!(authorize_admin(&admin).is_ok());
        for p in [&mgr_sess, &op_sess, &mgr_key, &op_key, &ro_key] {
            assert!(authorize_admin(p).is_err());
        }

        // manager check: admin/manager session or manager key
        for p in [&admin, &mgr_sess, &mgr_key] {
            assert!(authorize_manager(p).is_ok());
            assert!(p.can_view_confidential_notes());
        }
        for p in [&op_sess, &op_key, &ro_key] {
            assert!(authorize_manager(p).is_err());
            assert!(!p.can_view_confidential_notes());
        }

        // operator check: everything except readonly key
        for p in [&admin, &mgr_sess, &op_sess, &mgr_key, &op_key] {
            assert!(authorize_operator(p).is_ok());
        }
        assert!(authorize_operator(&ro_key).is_err());

        // session check: sessions only
        for p in [&admin, &mgr_sess, &op_sess] {
            assert!(authorize_session(p).is_ok());
        }
        for p in [&mgr_key, &op_key, &ro_key] {
            assert!(authorize_session(p).is_err());
        }

        // audit visibility scope
        assert_eq!(
            admin.audit_visibility_scope(),
            Some(AuditVisibilityScope::Full)
        );
        assert_eq!(
            mgr_sess.audit_visibility_scope(),
            Some(AuditVisibilityScope::Operational)
        );
        assert_eq!(
            mgr_key.audit_visibility_scope(),
            Some(AuditVisibilityScope::Operational)
        );
        assert_eq!(op_sess.audit_visibility_scope(), None);
        assert_eq!(op_key.audit_visibility_scope(), None);
        assert_eq!(ro_key.audit_visibility_scope(), None);
    }
}
