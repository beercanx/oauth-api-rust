mod graceful_shutdown;
mod token_exchange;
mod token;
mod grant;
mod token_introspection;

use axum::{serve, Router};
use std::io;
use tokio::net::TcpListener;
use token::InMemoryTokenRepository;
use token_exchange::TokenExchangeState;
use token_introspection::TokenIntrospectionState;
use crate::token::AccessToken;

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

    // TODO - Do we bother with services, or just continue with passing the repositories directly?
    let access_token_repository = InMemoryTokenRepository::<AccessToken>::new();

    let application = Router::new()
        .merge(token_exchange::route(TokenExchangeState {
            access_token_repository: access_token_repository.clone(), // TODO - Review if this is safe and the right thing to do
        }))
        .merge(token_introspection::route(TokenIntrospectionState {
            access_token_repository: access_token_repository.clone(), // TODO - Review if this is safe and the right thing to do
        }));

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