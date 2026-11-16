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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let shutdown = shutdown_signal()?;
    let addr = std::env::var("SKYOAUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(listener, skyoauth_service::app())
        .with_graceful_shutdown(shutdown)
        .await
}
