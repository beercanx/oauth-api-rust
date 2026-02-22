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

#[derive(Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenExchangeRequest {
    AuthorizationCode(AuthorizationCodeGrantRequest),
    Password(PasswordGrantRequest),
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
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
            AuthorizationCode(AuthorizationCodeGrantRequest { // TODO - Implement real validation
                code: request.get("code").unwrap().into(),
                redirect_uri: request.get("redirect_uri").unwrap().into(),
                code_verifier: request.get("code_verifier").map(|v| v.into()),
            })
        )),

        Some(grant_type) if grant_type.trim().is_empty() => Err(
            TokenExchangeResponse::invalid_parameter("grant_type")
        ),

        Some(grant_type) => Err(
            TokenExchangeResponse::Failure {
                error: ErrorType::UnsupportedGrantType,
                error_description: Some(format!("unsupported: {grant_type}")),
            }
        ),

        None => Err(TokenExchangeResponse::missing_parameter("grant_type")),
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

    use super::*;
    use assertables::*;
    use crate::token_exchange::request::validate_grant_type;

    macro_rules! input_parameters {
        ($($k:expr => $v:expr),* $(,)?) => {{
            HashMap::from([$(($k.into(), $v.into()),)*])
        }};
    }

    macro_rules! validate_err  {
        ($name:ident, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_err!(validate_grant_type($request)), $expected);
            }
        }
    }

    macro_rules! validate_ok  {
        ($name:ident, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_ok!(validate_grant_type($request)), $expected);
            }
        }
    }

    validate_err! {
        should_return_invalid_request_on_missing_grant_type,
        input_parameters! {},
        TokenExchangeResponse::missing_parameter("grant_type")
    }

    validate_err! {
        should_return_invalid_request_on_blank_grant_type,
        input_parameters! { "grant_type" => " " },
        TokenExchangeResponse::invalid_parameter("grant_type")
    }

    validate_err! {
        should_return_invalid_request_on_unsupported_grant_type,
        input_parameters! { "grant_type" => "aardvark" },
        TokenExchangeResponse::Failure {
            error: ErrorType::UnsupportedGrantType,
            error_description: Some("unsupported: aardvark".into())
        }
    }

    // TODO - should return invalid request on client unauthorised to use grant type
    // validate_err! {
    //     should_return_invalid_request_on_unauthorised_grant_type,
    //     input_parameters! { "grant_type" => "password" },
    //     TokenExchangeResponse::Failure {
    //         error: ErrorType::UnauthorizedClient,
    //         error_description: Some("not authorized to: password".into())
    //     }
    // }

    validate_ok! {
        should_return_valid_request_for_password_grant_type,
        input_parameters! { "grant_type" => "password", "username" => "aardvark", "password" => "" },
        TokenExchangeForm(Password(PasswordGrantRequest {
            username: "aardvark".into(),
            password: "".into(),
            scopes: None,
        }))
    }

    validate_ok! {
        should_return_valid_request_for_authorization_code_grant_type,
        input_parameters! {
            "grant_type" => "authorization_code",
            "code" => "1234567890",
            "redirect_uri" => "https://example.com/callback"
        },
        TokenExchangeForm(AuthorizationCode(AuthorizationCodeGrantRequest {
            code: "1234567890".into(),
            redirect_uri: "https://example.com/callback".into(),
            code_verifier: None,
        }))
    }
}