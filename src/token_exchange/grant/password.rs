use std::collections::HashMap;
use axum::response::Response;
use serde::Deserialize;
use crate::token::{AccessToken, InMemoryTokenRepository, TokenRepository, TokenType};
use crate::token_exchange::response::{invalid_parameter, missing_parameter, TokenExchangeResponse};

pub async fn handle_password_grant(request: PasswordGrantRequest) -> TokenExchangeResponse {

    println!("handle_password_grant({request:?})");

    // TODO - Implement it... and place the service/repository creation somewhere sensible.
    let access_token_repository= InMemoryTokenRepository::<AccessToken>::new();

    let access_token = AccessToken {
        id: uuid::Uuid::new_v4(),
    };

    access_token_repository.save_token(&access_token);


    TokenExchangeResponse::Success {
        access_token: access_token.id,
        token_type: TokenType::Bearer,
        expires_in: 7200,
        refresh_token: Some(uuid::Uuid::new_v4()),
        scope: request.scope,
        state: None,
    }
}

#[derive(Deserialize, Debug)]
pub struct PasswordGrantRequest {
    pub username: String,
    pub password: String,
    pub scope: Option<String>,
}

pub fn validate_password_grant(request: HashMap<String, String>) -> Result<PasswordGrantRequest, Response> {

    // principal := context.MustGet(client.AuthClientKey).(client.Principal)
    // case !principal.IsConfidential(), !principal.CanBeGranted(grant.Password):
    // TODO - Add client principal validation

    let username = match request.get("username") {
        None => return Err(missing_parameter("username")),
        Some(username) if username.is_empty() => return Err(invalid_parameter("username")),
        Some(username) => username,
    };

    let password = match request.get("password") {
        None => return Err(missing_parameter("password")),
        Some(password) => password,
    };

    // The requested scope is invalid, unknown, or malformed.
    let scope = match request.get("scope") {

        // case scopeOk && len(scopes.Value) == 0:
        Some(scope) if scope.is_empty() => return Err(invalid_parameter("scope")),

        // case len(rawScopes) != len(scopes.Value):
        // TODO - Check all requested scopes are supported

        // case !principal.CanBeIssued(scopes.Value):
        // TODO - Check is scopes can be issued to client principal

        scope => scope,
    };

    Ok(PasswordGrantRequest {
        // TODO - Add client principal
        username: username.clone(),
        password: password.clone(),
        scope: scope.cloned(),
    })
}
