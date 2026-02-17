use std::collections::HashMap;
use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use crate::token_exchange::grant::{validate_password_grant, PasswordGrantRequest};
use crate::token_exchange::request::TokenExchangeRequest::{AuthorizationCode, Password};
use crate::token_exchange::response::{missing_parameter, parameter_error_response, ErrorType, TokenExchangeResponse};

#[derive(Deserialize, Debug)]
pub struct AuthorizationCodeGrantRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

#[derive(Deserialize, Debug)]
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
            Ok(Form(request)) => validate_grant_type(request)
        }
    }
}

fn validate_grant_type(request: HashMap<String, String>) -> Result<TokenExchangeForm, Response> {
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
            parameter_error_response(ErrorType::UnsupportedGrantType, format!("unsupported: {grant_type}"))
        ),
        None => Err(missing_parameter("grant_type"))
    }
}

fn handle_form_rejection(rejection: FormRejection) -> Response {
    (rejection.status(), Json(TokenExchangeResponse::failure(
        ErrorType::InvalidRequest,
        rejection.body_text()
    ))).into_response()
}