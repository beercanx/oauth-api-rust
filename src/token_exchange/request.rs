use std::collections::HashMap;
use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use crate::client::{ClientPrincipal, GrantType};
use crate::token_exchange::grant::password::{validate_password_grant, PasswordGrantRequest};
use crate::token_exchange::request::TokenExchangeRequest::Password;
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};

#[derive(Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "grant_type", rename_all = "snake_case")]
pub enum TokenExchangeRequest {
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

        let principal = req.extensions()
            .get::<ClientPrincipal>()
            .cloned()
            .ok_or_else(|| handle_validation_failure(TokenExchangeResponse::Failure {
                error: ErrorType::InvalidRequest,
                error_description: Some("missing client authentication".into()),
            }))?;

        match Form::<HashMap<String, String>>::from_request(req, state).await {
            Err(rejection) => Err(handle_form_rejection(rejection)),
            Ok(Form(request)) => match validate_grant_type(principal, request) {
                Err(failure) => Err(handle_validation_failure(failure)),
                Ok(valid) => Ok(valid),
            }
        }
    }
}

pub fn validate_grant_type(principal: ClientPrincipal, request: HashMap<String, String>) -> Result<TokenExchangeForm, TokenExchangeResponse> {
    match request.get("grant_type").map(|s| s.parse::<GrantType>()) {

        None => Err(TokenExchangeResponse::missing_parameter("grant_type")),

        Some(Err(error_message)) => Err(
            TokenExchangeResponse::Failure {
                error: ErrorType::UnsupportedGrantType,
                error_description: Some(error_message),
            }
        ),

        Some(Ok(grant_type)) if !principal.can_perform_grant_type(&grant_type) => Err(
            TokenExchangeResponse::Failure {
                error: ErrorType::UnauthorizedClient,
                error_description: Some(format!("not authorized to: {:?}", grant_type)),
            }
        ),

        Some(Ok(GrantType::Password)) => Ok(TokenExchangeForm(
            Password(validate_password_grant(principal, request)?)
        )),
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
    use crate::client::ClientType;
    use crate::client::configuration::ClientConfiguration;
    use crate::token_exchange::request::validate_grant_type;

    macro_rules! input_parameters {
        ($($k:expr => $v:expr),* $(,)?) => {{
            HashMap::from([$(($k.into(), $v.into()),)*])
        }};
    }

    macro_rules! validate_err  {
        ($name:ident, $principal:expr, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_err!(validate_grant_type($principal, $request)), $expected);
            }
        }
    }

    macro_rules! validate_ok  {
        ($name:ident, $principal:expr, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_ok!(validate_grant_type($principal, $request)), $expected);
            }
        }
    }

    validate_err! {
        should_return_invalid_request_on_missing_grant_type,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! {},
        TokenExchangeResponse::missing_parameter("grant_type")
    }

    validate_err! {
        should_return_invalid_request_on_blank_grant_type,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "grant_type" => " " },
        TokenExchangeResponse::Failure {
            error: ErrorType::UnsupportedGrantType,
            error_description: Some("unsupported:  ".into())
        }
    }

    validate_err! {
        should_return_invalid_request_on_unsupported_grant_type,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "grant_type" => "aardvark" },
        TokenExchangeResponse::Failure {
            error: ErrorType::UnsupportedGrantType,
            error_description: Some("unsupported: aardvark".into())
        }
    }

    validate_err! {
        should_return_invalid_request_on_unauthorised_grant_type,
        ClientPrincipal::new_principal(ClientConfiguration {
            client_id: String::from("invalid").into(),
            client_type: ClientType::Confidential,
            redirect_uris: Default::default(),
            allowed_scopes: Default::default(),
            allowed_actions: Default::default(),
            allowed_grant_types: Default::default(),
        }),
        input_parameters! { "grant_type" => "password" },
        TokenExchangeResponse::Failure {
            error: ErrorType::UnauthorizedClient,
            error_description: Some("not authorized to: Password".into())
        }
    }

    validate_ok! {
        should_return_valid_request_for_password_grant_type,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "grant_type" => "password", "username" => "aardvark", "password" => "" },
        TokenExchangeForm(Password(PasswordGrantRequest {
            principal: ClientPrincipal::new_confidential_client("aardvark"),
            username: "aardvark".into(),
            password: "".into(),
            scopes: None,
        }))
    }

    // TODO - Re-enable once authorization code grant type is implemented
    // validate_ok! {
    //     should_return_valid_request_for_authorization_code_grant_type,
    //     input_parameters! {
    //         "grant_type" => "authorization_code",
    //         "code" => "1234567890",
    //         "redirect_uri" => "https://example.com/callback"
    //     },
    //     TokenExchangeForm(AuthorizationCode(AuthorizationCodeGrantRequest {
    //         code: "1234567890".into(),
    //         redirect_uri: "https://example.com/callback".into(),
    //         code_verifier: None,
    //     }))
    // }
}