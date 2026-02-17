use axum::extract::State;
use axum::http::StatusCode;
use axum::Router;
use axum::routing::post;
use axum::response::Json;
use crate::token::{AccessToken, TokenRepository};
use crate::token_exchange::grant::handle_password_grant;
use crate::token_exchange::response::TokenExchangeResponse;
use crate::token_exchange::response::ErrorType::UnsupportedGrantType;
use crate::token_exchange::request::{TokenExchangeForm, TokenExchangeRequest};

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
pub fn route<S, A>(state: TokenExchangeState<A>) -> Router<S>
where
    A: TokenRepository<AccessToken> + 'static
{
    Router::new()
        .route("/token", post(token_exchange_handler))
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenExchangeState<A: TokenRepository<AccessToken>> {
    pub access_token_repository: A,
}

async fn token_exchange_handler<A: TokenRepository<AccessToken>>(
    State(state): State<TokenExchangeState<A>>,
    TokenExchangeForm(request): TokenExchangeForm,
) -> (StatusCode, Json<TokenExchangeResponse>) {

    // TODO - Handle client principal

    println!("token_exchange_handler: {request:?}");

    let result = match request {
        TokenExchangeRequest::AuthorizationCode(_) => TokenExchangeResponse::Failure { // TODO - Implement
            error: UnsupportedGrantType,
            error_description: Some("unsupported grant type: authorization_code".into())
        },
        TokenExchangeRequest::Password(password_grant_request) => {
            handle_password_grant(state, password_grant_request).await
        },
    };

    let status = match result {
        TokenExchangeResponse::Failure { .. } => StatusCode::BAD_REQUEST,
        TokenExchangeResponse::Success { .. } => StatusCode::OK,
    };

    (status, Json(result))
}
