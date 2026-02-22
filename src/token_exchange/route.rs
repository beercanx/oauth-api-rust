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

#[cfg(test)]
mod integration_tests {

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/TokenRouteIntegrationTests.kt

    // TODO - InvalidHttpRequest
    //          - should only support post requests
    //          - should require client authentication
    //          - should only support url encoded form requests

    // TODO - InvalidTokenRequest
    //          - should return bad request for invalid token exchange requests

    // TODO - SuccessTokenRequest
    //          - should return ok for valid password grants
    //          - should return ok for valid authorisation code grants
    //          - should return ok for valid refresh token grants
    //          - should return ok for valid assertion grants
}