use axum::http::StatusCode;
use axum::{middleware, Extension, Json, Router};
use axum::extract::State;
use axum::routing::post;
use middleware::from_fn_with_state;
use serde::Serialize;
use tower::ServiceBuilder;
use crate::client::authentication::ClientAuthenticator;
use crate::client::{ClientAction, ConfidentialClient};
use crate::client::middleware::require_confidential_client_authentication;
use crate::token::AccessToken;
use crate::token::repository::TokenRepository;
use crate::token_introspection::middleware::require_confidential_client_action;

pub fn route<S, A, C>(state: TokenIntrospectionState<A, C>) -> Router<S>
where
    A: TokenRepository<AccessToken> + 'static,
    C: ClientAuthenticator + 'static
{
    Router::new()
        .route("/introspect", post(token_introspection_handler))
        .route_layer(
            ServiceBuilder::new()
                .layer(from_fn_with_state(state.client_authenticator.clone(), require_confidential_client_authentication::<C>))
                .layer(from_fn_with_state(ClientAction::Introspect, require_confidential_client_action))
        )
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenIntrospectionState<A: TokenRepository<AccessToken>, C: ClientAuthenticator> {
    pub access_token_repository: A,
    pub client_authenticator: C,
}

async fn token_introspection_handler<A : TokenRepository<AccessToken>, C: ClientAuthenticator>(
    State(state): State<TokenIntrospectionState<A, C>>,
    Extension(client) : Extension<ConfidentialClient>,
) -> (StatusCode, Json<TokenIntrospectionResponse>) {

    // TODO - Validate request
    // TODO - Actually implement

    match state.access_token_repository.get_token(uuid::Uuid::new_v4()) {
        Some(_) => (StatusCode::OK, Json(TokenIntrospectionResponse { active: true })),
        None => (StatusCode::OK, Json(TokenIntrospectionResponse { active: false })),
    }
}

#[derive(Serialize)]
struct TokenIntrospectionResponse {
    active: bool,
}
