// shared application state and startup database pool initialization

use crate::config::{verify_pool_role, AppConfig, ConfigError};
use crate::guards::rate_limit::RateLimiterState;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("invalid database connection url: {0}")]
    InvalidDatabaseUrl(String),

    #[error("failed to connect migration pool: {0}")]
    MigrationConnect(sqlx::Error),

    #[error("migration execution failed: {0}")]
    MigrationFailed(#[from] sqlx::migrate::MigrateError),

    #[error("failed to connect runtime database pool: {0}")]
    RuntimeConnect(sqlx::Error),

    #[error("database role verification failed: {0}")]
    RoleVerification(ConfigError),
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub rate_limiter: Arc<RateLimiterState>,
}

impl AppState {
    pub fn new(db: PgPool, config: Arc<AppConfig>) -> Self {
        let rate_limiter = Arc::new(RateLimiterState::new(
            config.rate_limit_auth_per_min,
            config.rate_limit_api_per_min,
        ));
        Self {
            db,
            config,
            rate_limiter,
        }
    }

    pub async fn from_config(config: AppConfig) -> Result<Self, StartupError> {
        if config.run_migrations {
            let mig_url = config.migration_database_url.as_deref().ok_or_else(|| {
                StartupError::Config(ConfigError::MissingVar(
                    "MIGRATION_DATABASE_URL".to_string(),
                ))
            })?;

            let mig_opts = PgConnectOptions::from_str(mig_url)
                .map_err(|e| StartupError::InvalidDatabaseUrl(e.to_string()))?;

            let mig_pool = PgPoolOptions::new()
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(mig_opts)
                .await
                .map_err(StartupError::MigrationConnect)?;

            // verify migration pool connects as penelope_owner before applying migrations
            if let Err(err) = verify_pool_role(&mig_pool, "penelope_owner").await {
                mig_pool.close().await;
                return Err(StartupError::RoleVerification(err));
            }

            let mig_result = sqlx::migrate!("./migrations").run(&mig_pool).await;
            mig_pool.close().await;
            mig_result?;
        }

        let app_opts = PgConnectOptions::from_str(&config.database_url)
            .map_err(|e| StartupError::InvalidDatabaseUrl(e.to_string()))?;

        let app_pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(app_opts)
            .await
            .map_err(StartupError::RuntimeConnect)?;

        // verify runtime pool connects as least-privilege penelope_app
        verify_pool_role(&app_pool, "penelope_app")
            .await
            .map_err(StartupError::RoleVerification)?;

        Ok(Self::new(app_pool, Arc::new(config)))
    }
}
