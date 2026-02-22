use std::collections::HashMap;
use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use crate::token_exchange::grant::{validate_password_grant, AuthorizationCodeGrantRequest, PasswordGrantRequest};
use crate::token_exchange::request::TokenExchangeRequest::{AuthorizationCode, Password};
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};

#[derive(Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenExchangeRequest {
    AuthorizationCode(AuthorizationCodeGrantRequest),
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
        match Form::<HashMap<String, String>>::from_request(req, state).await {
            Err(rejection) => Err(handle_form_rejection(rejection)),
            Ok(Form(request)) => match validate_grant_type(request) {
                Err(failure) => Err(handle_validation_failure(failure)),
                Ok(valid) => Ok(valid),
            }
        }
    }
}

fn validate_grant_type(request: HashMap<String, String>) -> Result<TokenExchangeForm, TokenExchangeResponse> {
    match request.get("grant_type") {
        Some(grant_type) if grant_type == "password" => Ok(TokenExchangeForm(
            Password(validate_password_grant(request)?)
        )),
        Some(grant_type) if grant_type == "authorization_code" => Ok(TokenExchangeForm(
            AuthorizationCode(AuthorizationCodeGrantRequest {
                code: "".to_string(),
                redirect_uri: "".to_string(),
                code_verifier: None,
            })
        )),
        Some(grant_type) => Err(
            TokenExchangeResponse::Failure {
                error: ErrorType::UnsupportedGrantType,
                error_description: Some(format!("unsupported: {grant_type}")),
            }
        ),
        None => Err(TokenExchangeResponse::missing_parameter("grant_type"))
    }
}

fn handle_validation_failure(failure: TokenExchangeResponse) -> Response {
    (StatusCode::BAD_REQUEST, Json(failure)).into_response()
}

fn handle_form_rejection(rejection: FormRejection) -> Response {
    (rejection.status(), Json(TokenExchangeResponse::Failure {
        error: ErrorType::InvalidRequest,
        error_description: Some(rejection.body_text()),
    })).into_response()
}

#[cfg(test)]
mod unit_tests {

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/TokenRequestValidationTest.kt

    // TODO - should return invalid request on missing grant type
    // TODO - should return invalid request on blank grant type
    // TODO - should return invalid request on invalid grant type
    // TODO - should return invalid request on client unauthorised to use grant type

    // TODO - should return valid request for valid grant type for given client
}