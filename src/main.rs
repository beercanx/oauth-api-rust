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
mod schema;
mod database;

use crate::util::diesel_migrations::run_diesel_migrations;
use crate::util::diesel_pool::create_pool;
use anyhow::{Context, Result};
use axum::{serve, Router};
use client::authentication::ClientAuthenticationService;
use client::configuration::DieselClientConfigurationRepository;
use client::secret::DieselClientSecretRepository;
use token::repository::DieselAccessTokenRepository;
use token_exchange::TokenExchangeState;
use token_introspection::TokenIntrospectionState;
use tokio::net::TcpListener;

// TODO List:
//  - Token endpoint
//  - Client authentication
//  - User authentication
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
//  - Error handling, including 500s
#[tokio::main]
async fn main() -> Result<()> {

    // TODO - Do we bother with services?
    //        or just continue with passing the repositories directly?
    //        or do we just pass connection pools and do await with services and repositories?

    let pool = create_pool("file:target/db/diesel.sqlite3")?;

    run_diesel_migrations(&pool).await?;

    let access_token_repository = DieselAccessTokenRepository::new(pool.clone());

    let client_secret_repository = DieselClientSecretRepository::new(pool.clone());
    let client_configuration_repository = DieselClientConfigurationRepository::new(pool.clone());

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