use crate::config::InitialAdminConfig;
use crate::crypto;
use crate::error::AppError;
use crate::services::audit::{AuditEventInput, AuditService};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

// arbitrary fixed lock id so concurrent server starts serialize on bootstrap
const BOOTSTRAP_ADVISORY_LOCK_KEY: i64 = 0x5045_4E45_4C4F_0201;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Disabled,
    SkippedExistingUsers { existing_count: i64 },
    CreatedAdmin { user_id: Uuid, email: String },
}

// inserts the initial admin user and audit row inside an existing transaction (only exported for tests)
#[cfg(feature = "test-helpers")]
pub async fn insert_bootstrap_admin_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    admin_cfg: &InitialAdminConfig,
) -> Result<(Uuid, String), AppError> {
    insert_bootstrap_admin_in_tx_inner(tx, admin_cfg).await
}

async fn insert_bootstrap_admin_in_tx_inner(
    tx: &mut Transaction<'_, Postgres>,
    admin_cfg: &InitialAdminConfig,
) -> Result<(Uuid, String), AppError> {
    let email = admin_cfg.email.trim().to_ascii_lowercase();
    let full_name = admin_cfg.full_name.trim().to_string();
    let pw_clone = admin_cfg.password.clone();

    let password_hash = tokio::task::spawn_blocking(move || crypto::hash_password(&pw_clone))
        .await
        .map_err(|e| AppError::internal(format!("password hash task failed: {e}")))?
        .map_err(|e| AppError::internal(format!("failed to hash admin password: {e}")))?;

    let user_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO public.users (id, email, full_name, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, 'admin', TRUE)
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .bind(&full_name)
    .bind(&password_hash)
    .execute(&mut **tx)
    .await?;

    AuditService::record_event(
        tx,
        &AuditEventInput {
            actor_user_id: None,
            actor_api_key_id: None,
            actor_label: "system:bootstrap".to_string(),
            action: "user.bootstrap.admin".to_string(),
            entity_type: "user".to_string(),
            entity_id: Some(user_id.to_string()),
            ip_address: String::new(),
            details: serde_json::json!({
                "email": email,
                "role": "admin"
            }),
        },
    )
    .await?;

    Ok((user_id, email))
}

// creates the first admin only when BOOTSTRAP_INITIAL_ADMIN=true and users table is empty
pub async fn bootstrap_initial_admin(
    pool: &PgPool,
    initial_admin: Option<&InitialAdminConfig>,
) -> Result<BootstrapOutcome, AppError> {
    let Some(admin_cfg) = initial_admin else {
        return Ok(BootstrapOutcome::Disabled);
    };

    let mut tx = pool.begin().await?;

    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_ADVISORY_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    let existing_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM public.users")
        .fetch_one(&mut *tx)
        .await?;

    if existing_count > 0 {
        tx.commit().await?;
        return Ok(BootstrapOutcome::SkippedExistingUsers { existing_count });
    }

    let (user_id, email) = insert_bootstrap_admin_in_tx_inner(&mut tx, admin_cfg).await?;
    tx.commit().await?;

    Ok(BootstrapOutcome::CreatedAdmin { user_id, email })
}
