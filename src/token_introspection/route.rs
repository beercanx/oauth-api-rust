use crate::client::authentication::ClientAuthenticator;
use crate::client::middleware::require_confidential_client_authentication;
use crate::client::{ClientAction, ConfidentialClient};
use crate::token::repository::TokenRepository;
use crate::token::{AccessToken, TokenType};
use crate::token_introspection::middleware::require_confidential_client_action;
use crate::token_introspection::request::TokenIntrospectionForm;
use crate::token_introspection::response::TokenIntrospectionResponse;
use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{middleware, Extension, Json, Router};
use middleware::from_fn_with_state;
use tower::ServiceBuilder;

pub fn route<S, A, C>(state: TokenIntrospectionState<A, C>) -> Router<S>
where
    A: TokenRepository<AccessToken> + 'static,
    C: ClientAuthenticator + 'static,
{
    Router::new()
        .route("/introspect", post(token_introspection_handler))
        .route_layer(
            ServiceBuilder::new()
                .layer(from_fn_with_state(
                    state.client_authenticator.clone(),
                    require_confidential_client_authentication::<C>,
                ))
                .layer(from_fn_with_state(
                    ClientAction::Introspect,
                    require_confidential_client_action,
                )),
        )
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenIntrospectionState<A: TokenRepository<AccessToken>, C: ClientAuthenticator> {
    pub access_token_repository: A,
    pub client_authenticator: C,
}

async fn token_introspection_handler<A: TokenRepository<AccessToken>, C: ClientAuthenticator>(
    State(state): State<TokenIntrospectionState<A, C>>,
    Extension(_client): Extension<ConfidentialClient>,
    TokenIntrospectionForm(request): TokenIntrospectionForm,
) -> Result<impl IntoResponse, StatusCode> {

    // TODO - Validate request
    // TODO - Actually implement
    // TODO - Check for expired
    // TODO - Check for not valid yet

    match state
        .access_token_repository
        .get_token(request.token.into())
        .await
    {
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR), // TODO - Add error logging
        Ok(None) => Ok(Json(TokenIntrospectionResponse::Inactive {
            active: false,
        })),
        Ok(Some(token)) => Ok(Json(TokenIntrospectionResponse::Active {
            active: true,
            scope: Some(token.scopes),
            client_id: Some(token.client_id),
            username: Some(token.username),
            token_type: Some(TokenType::Bearer),
            expires_at: Some(token.expires_at.and_utc().timestamp()),
            issued_at: Some(token.issued_at.and_utc().timestamp()),
            not_before: Some(token.not_before.and_utc().timestamp()),
        })),
    }
}
