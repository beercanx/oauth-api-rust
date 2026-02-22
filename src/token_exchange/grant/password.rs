use std::collections::HashMap;
use serde::Deserialize;
use crate::token::{AccessToken, TokenRepository, TokenType};
use crate::token_exchange::response::{TokenExchangeResponse};
use crate::token_exchange::route::TokenExchangeState;
use crate::scope::{parse_scopes, Scope};

#[derive(Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PasswordGrantRequest {
    pub username: String,
    pub password: String,
    pub scopes: Option<Vec<Scope>>,
}

pub async fn handle_password_grant<A>(
    state: TokenExchangeState<A>,
    request: PasswordGrantRequest
) -> TokenExchangeResponse
where
    A: TokenRepository<AccessToken>,
{

    // TODO - Implement it...

    let access_token = AccessToken {
        id: uuid::Uuid::new_v4(),
    };

    state.access_token_repository.save_token(&access_token);

    TokenExchangeResponse::Success {
        access_token: access_token.id,
        token_type: TokenType::Bearer,
        expires_in: 7200,
        refresh_token: Some(uuid::Uuid::new_v4()),
        scope: request.scopes.map(|scopes| scopes // TODO - Update `Success` with Option<Vec<Scope>> with space delimited string serialisation
            .into_iter()
            .map(|scope| scope.name)
            .collect::<Vec<String>>()
            .join(" ")
        ),
        state: None,
    }
}

pub fn validate_password_grant(request: HashMap<String, String>) -> Result<PasswordGrantRequest, TokenExchangeResponse> {

    // principal := context.MustGet(client.AuthClientKey).(client.Principal)
    // case !principal.IsConfidential(), !principal.CanBeGranted(grant.Password):
    // TODO - Add client principal validation

    let username = match request.get("username") {
        None => Err(TokenExchangeResponse::missing_parameter("username"))?,
        Some(username) if username.trim().is_empty() => Err(TokenExchangeResponse::invalid_parameter("username"))?,
        Some(username) => username,
    };

    let password = match request.get("password") {
        None => Err(TokenExchangeResponse::missing_parameter("password"))?,
        Some(password) => password,
    };
    
    let scopes = parse_scopes(request.get("scope"))
        .map_err(|_| TokenExchangeResponse::invalid_parameter("scope"))?;

    // case !principal.CanBeIssued(scopes):
    // TODO - Check all scopes can be issued to client principal
    
    Ok(PasswordGrantRequest {
        // TODO - Add client principal
        username: username.into(),
        password: password.into(),
        scopes: scopes.into(),
    })
}

#[cfg(test)]
mod unit_tests {

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/PasswordValidationTest.kt

    use super::*;
    use assertables::*;
    use crate::token_exchange::response::ErrorType;

    macro_rules! input_parameters {
        ($($k:expr => $v:expr),* $(,)?) => {{
            core::convert::From::from([$(($k.into(), $v.into()),)*])
        }};
    }

    macro_rules! expected_failure {
        ($error:expr, $error_description:expr) => {{
            TokenExchangeResponse::Failure {
                error: $error,
                error_description: Some($error_description.into()),
            }
        }};
    }
    
    macro_rules! validate_err {
        ($name:ident, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_err!(validate_password_grant($request)), $expected);
            }
        }
    }

    macro_rules! validate_ok {
        ($name:ident, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_ok!(validate_password_grant($request)), $expected);
            }
        }
    }

    // TODO - should return invalid request for a non confidential client
    // TODO - should return invalid request for an unauthorised client

    validate_err! {
        should_return_invalid_request_on_missing_username,
        input_parameters! { "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "missing parameter: username" }
    }

    validate_err! {
        should_return_invalid_request_on_blank_username,
        input_parameters! { "username" => " ", "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "invalid parameter: username" }
    }

    validate_err! {
        should_return_invalid_request_on_missing_password,
        input_parameters! { "username" => "aardvark", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "missing parameter: password" }
    }

    validate_err! {
        should_return_invalid_request_on_blank_scope,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => " " },
        expected_failure! { ErrorType::InvalidRequest, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_invalid_scope,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "cicada" },
        expected_failure! { ErrorType::InvalidRequest, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_invalid_scope_and_a_valid_scope,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic cicada" },
        expected_failure! { ErrorType::InvalidRequest, "invalid parameter: scope" }
    }

    // TODO - should return invalid request on unauthorised scopes

    validate_ok! {
        should_return_valid_request_if_only_scope_is_not_provided,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>" },
        PasswordGrantRequest {
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: None,
        }
    }

    validate_ok! {
        should_return_valid_request_if_only_one_scope_is_provided,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic" },
        PasswordGrantRequest {
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: Some(Vec::from([Scope::from("basic")])),
        }
    }

    validate_ok! {
        should_return_valid_request_if_multiple_scopes_are_provided,
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic read write" },
        PasswordGrantRequest {
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: Some(Vec::from(["basic", "read", "write"].map(Scope::from))),
        }
    }
}