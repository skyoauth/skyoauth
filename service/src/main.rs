use tokio::{net::TcpListener, signal};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr = std::env::var("SKYOAUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, skyoauth_service::app())
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await
}
