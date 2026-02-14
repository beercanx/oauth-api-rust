use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};

#[derive(Deserialize, Debug)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenExchangeRequest {
    Password(PasswordGrantRequest),
}

#[derive(Deserialize, Debug)]
pub struct PasswordGrantRequest {
    pub username: String,
    pub password: String,
    pub scope: Option<String>,
}

pub struct TokenExchangeForm(pub TokenExchangeRequest);

// The request is a URL encoded form, but the responses are JSON.
impl<S> FromRequest<S> for TokenExchangeForm
where
    S: Send + Sync,
    Form<TokenExchangeRequest>: FromRequest<S, Rejection = FormRejection>,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Form::<TokenExchangeRequest>::from_request(req, state)
            .await
            .map(|Form(value)| TokenExchangeForm(value))
            .map_err(|rejection| {

                let body = TokenExchangeResponse::Failure {
                    error: ErrorType::InvalidRequest,
                    error_description: Some(rejection.body_text()),
                };

                // "Failed to deserialize form body: grant_type: unknown variant `aardvark`, expected `password`"
                // TODO - Handle no such grant type
                // UnsupportedGrantType

                eprintln!("Form parsing failed: {rejection:?}");

                (rejection.status(), Json(body)).into_response()
            })
    }
}