use axum::http::StatusCode;
use axum::Router;
use axum::routing::post;
use axum::response::Json;
use crate::token_exchange::grant::handle_password_grant;
use crate::token_exchange::response::TokenExchangeResponse;
use crate::token_exchange::request::{TokenExchangeForm, TokenExchangeRequest};
use crate::token_exchange::response::ErrorType::UnsupportedGrantType;

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
pub fn route() -> Router {
    Router::new()
        .route("/token", post(token_exchange_handler))
}

#[axum::debug_handler]
async fn token_exchange_handler(TokenExchangeForm(request): TokenExchangeForm) -> (StatusCode, Json<TokenExchangeResponse>) {

    // TODO - Handle client principal

    println!("token_exchange_handler: {request:?}");

    let result = match request {
        TokenExchangeRequest::AuthorizationCode(_) => TokenExchangeResponse::Failure { // TODO - Implement
            error: UnsupportedGrantType,
            error_description: Some("unsupported grant type: authorization_code".into())
        },
        TokenExchangeRequest::Password(password_grant_request) => {
            handle_password_grant(password_grant_request).await
        },
    };

    let status = match result {
        TokenExchangeResponse::Failure { .. } => StatusCode::BAD_REQUEST,
        TokenExchangeResponse::Success { .. } => StatusCode::OK,
    };

    (status, Json(result))
}
