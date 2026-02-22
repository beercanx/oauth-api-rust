use axum::http::StatusCode;
use axum::{Json, Router};
use axum::extract::State;
use axum::routing::post;
use serde::Serialize;
use crate::token::{AccessToken, TokenRepository};

pub fn route<S, A: TokenRepository<AccessToken> + 'static>(state: TokenIntrospectionState<A>) -> Router<S> {
    Router::new()
        .route("/introspect", post(token_introspection_handler))
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenIntrospectionState<A: TokenRepository<AccessToken>> {
    pub access_token_repository: A,
}

async fn token_introspection_handler<A : TokenRepository<AccessToken>>(
    State(state): State<TokenIntrospectionState<A>>
) -> (StatusCode, Json<TokenIntrospectionResponse>) {

    // TODO - Actually implement

    match state.access_token_repository.get_token(uuid::Uuid::new_v4()) {
        Some(_) => (StatusCode::OK, Json(TokenIntrospectionResponse { active: true })),
        None => (StatusCode::OK, Json(TokenIntrospectionResponse { active: false })),
    }
}

#[derive(Serialize)]
pub struct TokenIntrospectionResponse {
    pub active: bool,
}
