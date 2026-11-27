use penelope_backend::config::AppConfig;
use penelope_backend::services::{bootstrap_initial_admin, BootstrapOutcome};
use penelope_backend::{routes, AppState};
use std::net::SocketAddr;
use std::process;
use tracing_subscriber::EnvFilter;

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!("failed to listen for ctrl+c signal: {}", err);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!("failed to install sigterm handler: {}", err);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "penelope_backend=info,tower_http=info".into());
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let config = match AppConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!("failed to load configuration: {}", err);
            process::exit(1);
        }
    };

    let bind_addr = format!("{}:{}", config.server_host, config.server_port);

    let state = match AppState::from_config(config).await {
        Ok(st) => st,
        Err(err) => {
            tracing::error!("failed to initialize application state: {}", err);
            process::exit(1);
        }
    };

    match bootstrap_initial_admin(&state.db, state.config.initial_admin.as_ref()).await {
        Ok(BootstrapOutcome::Disabled) => {}
        Ok(BootstrapOutcome::SkippedExistingUsers { existing_count }) => {
            tracing::info!(
                "initial admin bootstrap skipped (found {} existing users)",
                existing_count
            );
        }
        Ok(BootstrapOutcome::CreatedAdmin { user_id, email }) => {
            tracing::info!("created initial admin account '{}' (id={})", email, user_id);
        }
        Err(err) => {
            tracing::error!("initial admin bootstrap failed: {}", err);
            process::exit(1);
        }
    }

    let app = routes::build_router(state);

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!("failed to bind tcp listener on {}: {}", bind_addr, err);
            process::exit(1);
        }
    };

    tracing::info!(
        "penelope backend v{} listening on {}",
        penelope_backend::crate_version(),
        bind_addr
    );

    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        tracing::error!("http server exited with error: {}", err);
        process::exit(1);
    }
}
