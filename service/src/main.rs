use std::process::ExitCode;

use skyoauth_service::persistence::{self, DatabaseConfig};
use tokio::{net::TcpListener, signal};
use tracing_subscriber::EnvFilter;

/// Installs the signal handlers and returns a future that resolves on Ctrl-C
/// (SIGINT) or, on Unix, SIGTERM, the normal stop signal for containers and
/// process supervisors. The handlers are registered before this returns, so
/// no signal sent afterwards takes the default action.
fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    #[cfg(unix)]
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    Ok(async move {
        let ctrl_c = async {
            let _ = signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let terminate = async {
            sigterm.recv().await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => {},
            () = terminate => {},
        }
    })
}

const USAGE: &str = "usage: skyoauth-service [migrate]

  (no command)  serve HTTP on $SKYOAUTH_ADDR (default 127.0.0.1:8080)
  migrate       apply pending database migrations from $SKYOAUTH_DATABASE_URL, then exit";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let mut args = std::env::args().skip(1);
    let result = match (args.next().as_deref(), args.next()) {
        (None, _) => serve().await.map_err(|err| err.to_string()),
        (Some("migrate"), None) => migrate().await,
        (Some("-h" | "--help" | "help"), None) => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> std::io::Result<()> {
    let shutdown = shutdown_signal()?;
    let addr = std::env::var("SKYOAUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, skyoauth_service::app())
        .with_graceful_shutdown(shutdown)
        .await
}

/// Applies pending migrations. This is the only path that changes the
/// schema; the server does not migrate on start.
async fn migrate() -> Result<(), String> {
    let config = DatabaseConfig::from_env().map_err(|err| err.to_string())?;
    tracing::info!(database = ?config, "connecting");
    let pool = persistence::connect(&config)
        .await
        .map_err(|err| format!("cannot connect to the database: {err}"))?;
    let result = persistence::migrate(&pool).await;
    pool.close().await;
    result.map_err(|err| format!("migration failed: {err}"))?;
    let version = persistence::MIGRATOR.iter().map(|m| m.version).max();
    tracing::info!(version, "database schema is up to date");
    Ok(())
}
