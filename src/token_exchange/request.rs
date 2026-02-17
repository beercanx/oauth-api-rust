use std::collections::HashMap;
use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::http::status::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use crate::token_exchange::grant::{validate_password_grant, PasswordGrantRequest};
use crate::token_exchange::request::TokenExchangeRequest::Password;
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};

#[derive(Deserialize, Debug)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenExchangeRequest {
    Password(PasswordGrantRequest),
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
        Form::<HashMap<String, String>>::from_request(req, state)
            .await
            .map_err(|rejection| {
                (rejection.status(), Json(TokenExchangeResponse::failure(
                    ErrorType::InvalidRequest,
                    rejection.body_text()
                ))).into_response()
            })
            .and_then(|Form(request)| {
                match request.get("grant_type") {
                    Some(grant_type) if grant_type == "password" => Ok(TokenExchangeForm(
                        Password(validate_password_grant(request)?)
                    )),
                    Some(grant_type) => Err(
                        (StatusCode::BAD_REQUEST, Json(TokenExchangeResponse::failure(
                            ErrorType::UnsupportedGrantType,
                            format!("unsupported: {grant_type}"),
                        ))).into_response()
                    ),
                    None => Err(
                        (StatusCode::BAD_REQUEST, Json(TokenExchangeResponse::failure(
                            ErrorType::InvalidRequest,
                            "missing parameter: grant_type",
                        ))).into_response()
                    )
                }
            })
    }
}