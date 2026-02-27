#![forbid(unsafe_code)]

mod scope;
mod token;
mod token_exchange;
mod token_introspection;
mod graceful_shutdown;
mod client;
mod util;

use axum::{serve, Router};
use std::io;
use tokio::net::TcpListener;
use client::authentication::ClientAuthenticationService;
use client::configuration::InMemoryClientConfigurationRepository;
use client::secret::InMemoryClientSecretRepository;
use token::AccessToken;
use token::repository::InMemoryTokenRepository;
use token_exchange::TokenExchangeState;
use token_introspection::TokenIntrospectionState;

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
    let client_secret_repository = InMemoryClientSecretRepository::new();
    let client_configuration_repository = InMemoryClientConfigurationRepository::new();

    let client_authenticator = ClientAuthenticationService::new(
        client_secret_repository.clone(),
        client_configuration_repository.clone(),
    );
    
    let application = Router::new()
        .merge(token_exchange::route(TokenExchangeState {
            access_token_repository: access_token_repository.clone(),
            client_authenticator: client_authenticator.clone(),
        }))
        .merge(token_introspection::route(TokenIntrospectionState {
            access_token_repository: access_token_repository.clone(),
            client_authenticator: client_authenticator.clone(),
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