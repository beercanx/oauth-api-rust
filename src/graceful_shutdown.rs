use tokio::signal;

pub async fn signal() {

    let ctrl_c = async {

        println!("Waiting for a ctrl-c to trigger a graceful shutdown.");

        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");

        println!("Received a ctrl-c event, shutting down gracefully.");
    };

    #[cfg(unix)]
    let terminate = async {

        println!("Waiting for a SIGTERM to trigger a graceful shutdown.");

        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;

        println!("Received a SIGTERM event, shutting down gracefully.");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
