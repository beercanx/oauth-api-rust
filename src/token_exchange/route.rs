use axum::http::StatusCode;
use axum::{Form, Router};
use axum::extract::rejection::FormRejection;
use axum::routing::post;
use axum::response::Json;
use serde::Deserialize;
use crate::token::TokenType;
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};

pub fn route() -> Router {
    Router::new()
        .route("/token", post(token_exchange_handler))
}

#[derive(Deserialize, Debug)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum TokenExchangeRequest {
    Password { username: String, password: String, scope: String, state: String },
}

#[axum::debug_handler]
async fn token_exchange_handler(payload: Result<Form<TokenExchangeRequest>, FormRejection>) -> (StatusCode, Json<TokenExchangeResponse>) {

    // TODO - Handle client principal

    // TODO - Add detailed validation per grant type
    let request = match payload {
        Err(_) => {
            eprintln!("Received invalid token exchange request: {payload:?}");
            // TODO - Reconsider the short circuit as it won't work once logic is extracted.
            return (StatusCode::BAD_REQUEST, Json(TokenExchangeResponse::Failure{
                error: ErrorType::InvalidRequest,
                error_description: "".to_string(),
            }))
        },
        Ok(Form(body)) => {
            println!("Received token exchange request: {body:?}");
            body
        }
    };

    let result = match request {
        TokenExchangeRequest::Password { username, password, scope, state } => {
            handle_password_grant(username, password, scope, state).await
        },
    };

    match result {
        TokenExchangeResponse::Failure { .. } => (StatusCode::BAD_REQUEST, Json(result)),
        TokenExchangeResponse::Success { .. } => (StatusCode::OK, Json(result)),
    }
}

async fn handle_password_grant(username: String, password: String, scope: String, state: String) -> TokenExchangeResponse {

    println!("handle_password_grant(username: {username:?}, password: {password:?}, scope: {scope:?}, state: {state:?})");

    // TODO - Implement it...

    TokenExchangeResponse::Success {
        access_token: uuid::Uuid::new_v4(),
        token_type: TokenType::Bearer,
        expires_in: 7200,
        refresh_token: Some(uuid::Uuid::new_v4()),
        scope: Some(scope),
        state: Some(state),
    }
}
