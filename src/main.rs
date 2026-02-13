mod graceful_shutdown;
mod token_exchange;
mod token;
mod grant;

use axum::{serve, Router};
use std::io;
use tokio::net::TcpListener;

// TODO List:
//  - Token endpoint
//  - Client authentication
//  - User authentication
//  - Access token repository
//  - Introspection endpoint
//  - Logging
//  - Metrics
//  - Request/Tracking IDs
//  - TLS Termination
//  - HSTS
//  - Compression
//  - Caching Headers
//  - CORS
//  - Sessions [authenticate/authenticated]
//  - Access Log
//  - Database support
#[tokio::main]
async fn main() -> io::Result<()> {

    let application = Router::new().merge(token_exchange::route());

    // TODO - Extract into configuration
    let tcp_listener = TcpListener::bind("127.0.0.1:8080") // Change :8080 to :0 for a random port number
        .await?;

    println!();
    println!("Listening on http://{}", tcp_listener.local_addr()?);
    println!();

    serve(tcp_listener, application)
        .with_graceful_shutdown(graceful_shutdown::signal())
        .await?;

    Ok(())
}