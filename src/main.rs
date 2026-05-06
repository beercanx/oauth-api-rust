#![forbid(unsafe_code)]

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
)]
#![warn(
    clippy::pedantic,
)]
mod scope;
mod token;
mod token_exchange;
mod token_introspection;
mod graceful_shutdown;
mod client;
mod util;

use std::error::Error;
use axum::{serve, Router};
use tokio::net::TcpListener;
use client::authentication::ClientAuthenticationService;
use client::configuration::InMemoryClientConfigurationRepository;
use client::secret::InMemoryClientSecretRepository;
use token::repository::DieselSqliteAccessTokenRepository;
use token_exchange::TokenExchangeState;
use token_introspection::TokenIntrospectionState;

use anyhow::{Context, Result};

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
//  - Error handling, including 500s
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {

    // TODO - Do we bother with services, or just continue with passing the repositories directly?
    // let access_token_repository = InMemoryTokenRepository::<AccessToken>::new();

    let access_token_repository = token::repository::SqlxSqliteAccessTokenRepository
        ::new("file:target/db/access_tokens.sqlite3")
        .await?;

    // let access_token_repository = DieselSqliteAccessTokenRepository
    //     ::new("file:target/db/access_tokens.sqlite3")?;

    //access_token_repository.run_diesel_migrations()?;

    let client_secret_repository = InMemoryClientSecretRepository::new(); // "file:target/db/client_secrets.sqlite3"
    let client_configuration_repository = InMemoryClientConfigurationRepository::new(); // "file:target/db/client_configurations.sqlite3"

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
        .await
        .with_context(|| "Failed to bind to TCP listener")?;

    let local_address = tcp_listener
        .local_addr()
        .with_context(|| "Failed to get local tcp address")?;

    println!();
    println!("Listening on http://{local_address}");
    println!();

    serve(tcp_listener, application)
        .with_graceful_shutdown(graceful_shutdown::signal())
        .await?;

    Ok(())
}