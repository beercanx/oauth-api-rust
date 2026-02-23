use std::collections::HashMap;
use serde::Deserialize;
use ClientPrincipal::Confidential;
use GrantType::Password;
use crate::client::authentication::ClientAuthenticator;
use crate::client::{ClientPrincipal, ConfidentialClient, GrantType};
use crate::token::{AccessToken, TokenType};
use crate::token::repository::TokenRepository;
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};
use crate::token_exchange::route::TokenExchangeState;
use crate::scope::Scopes;
use crate::scope::parser::parse_scopes;

#[derive(Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PasswordGrantRequest {
    pub principal: ConfidentialClient,
    pub username: String,
    pub password: String,
    pub scopes: Option<Scopes>,
}

pub async fn handle_password_grant<A, C>(
    state: TokenExchangeState<A, C>,
    request: PasswordGrantRequest
) -> TokenExchangeResponse
where
    A: TokenRepository<AccessToken>,
    C: ClientAuthenticator,
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
        scope: request.scopes,
        state: None,
    }
}

pub fn validate_password_grant(principal: ClientPrincipal, request: HashMap<String, String>) -> Result<PasswordGrantRequest, TokenExchangeResponse> {
    let client = match principal {
        Confidential(client) if client.can_perform_grant_type(&Password) => client,
        _ => Err(TokenExchangeResponse::Failure {
            error: ErrorType::UnauthorizedClient,
            error_description: Some(format!("not authorized to: {:?}", Password)),
        })?,
    };

    let username = match request.get("username") {
        None => Err(TokenExchangeResponse::missing_parameter("username"))?,
        Some(username) if username.trim().is_empty() => Err(TokenExchangeResponse::invalid_parameter("username"))?,
        Some(username) => username,
    };

    let password = match request.get("password") {
        None => Err(TokenExchangeResponse::missing_parameter("password"))?,
        Some(password) => password,
    };

    let maybe_scopes = match parse_scopes(request.get("scope")) {
        Err(_) => Err(TokenExchangeResponse::Failure {
            error: ErrorType::InvalidScope,
            error_description: Some("invalid parameter: scope".into()),
        })?,
        Ok(Some(Scopes(scopes))) if !scopes.iter().all(|scope| client.can_be_issued(scope)) => {
            Err(TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            })?
        }
        Ok(maybe_scopes) => maybe_scopes
    };

    Ok(PasswordGrantRequest {
        principal: client,
        username: username.into(),
        password: password.into(),
        scopes: maybe_scopes,
    })
}

#[cfg(test)]
mod unit_tests {

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/PasswordValidationTest.kt

    use super::*;
    use assertables::*;
    use std::collections::HashSet;
    use crate::client::ClientType;
    use crate::client::configuration::ClientConfiguration;
    use crate::scope::Scope;
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
        ($name:ident, $principal:expr, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_err!(validate_password_grant($principal, $request)), $expected);
            }
        }
    }

    macro_rules! validate_ok {
        ($name:ident, $principal:expr, $request:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(assert_ok!(validate_password_grant($principal, $request)), $expected);
            }
        }
    }

    validate_err! {
        should_return_invalid_request_for_a_public_client,
        ClientPrincipal::new_public_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::UnauthorizedClient, "not authorized to: Password" }
    }

    validate_err! {
        should_return_invalid_request_for_an_unauthorised_client,
        ClientPrincipal::new_principal(ClientConfiguration {
            client_id: String::from("unauthorised").into(),
            client_type: ClientType::Confidential,
            redirect_uris: Default::default(),
            allowed_scopes: Default::default(),
            allowed_actions: Default::default(),
            allowed_grant_types: Default::default(),
        }),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::UnauthorizedClient, "not authorized to: Password" }
    }

    validate_err! {
        should_return_invalid_request_on_missing_username,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "missing parameter: username" }
    }

    validate_err! {
        should_return_invalid_request_on_blank_username,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => " ", "password" => "<REDACTED>", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "invalid parameter: username" }
    }

    validate_err! {
        should_return_invalid_request_on_missing_password,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "scope" => "read write" },
        expected_failure! { ErrorType::InvalidRequest, "missing parameter: password" }
    }

    validate_err! {
        should_return_invalid_request_on_blank_scope,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => " " },
        expected_failure! { ErrorType::InvalidScope, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_invalid_scope,
        ClientPrincipal::new_principal(ClientConfiguration {
            client_id: String::from("aardvark").into(),
            client_type: ClientType::Confidential,
            redirect_uris: Default::default(),
            // See: src/scope/parser.rs -> is_valid_scope() for hard wired valid scopes
            allowed_scopes: HashSet::from([Scope::from("invalid")]),
            allowed_actions: Default::default(),
            allowed_grant_types: HashSet::from([Password]),
        }),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "invalid" },
        expected_failure! { ErrorType::InvalidScope, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_invalid_scope_and_a_valid_scope,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic cicada" },
        expected_failure! { ErrorType::InvalidScope, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_duplicated_valid_scopes,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic basic" },
        expected_failure! { ErrorType::InvalidScope, "invalid parameter: scope" }
    }

    validate_err! {
        should_return_invalid_request_with_an_unauthorised_scope,
        ClientPrincipal::new_principal(ClientConfiguration {
            client_id: String::from("aardvark").into(),
            client_type: ClientType::Confidential,
            redirect_uris: Default::default(),
            allowed_scopes: HashSet::from([Scope::from("read")]),
            allowed_actions: Default::default(),
            allowed_grant_types: HashSet::from([Password]),
        }),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "write" },
        expected_failure! { ErrorType::InvalidScope, "invalid parameter: scope" }
    }

    validate_ok! {
        should_return_valid_request_if_only_scope_is_not_provided,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>" },
        PasswordGrantRequest {
            principal: ClientPrincipal::new_confidential_client("aardvark"),
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: None,
        }
    }

    validate_ok! {
        should_return_valid_request_if_only_one_scope_is_provided,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic" },
        PasswordGrantRequest {
            principal: ClientPrincipal::new_confidential_client("aardvark"),
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: Some(Scopes(HashSet::from([Scope::from("basic")]))),
        }
    }

    validate_ok! {
        should_return_valid_request_if_multiple_scopes_are_provided,
        ClientPrincipal::new_confidential_principal("aardvark"),
        input_parameters! { "username" => "aardvark", "password" => "<REDACTED>", "scope" => "basic read write" },
        PasswordGrantRequest {
            principal: ClientPrincipal::new_confidential_client("aardvark"),
            username: "aardvark".into(),
            password: "<REDACTED>".into(),
            scopes: Some(Scopes(HashSet::from(["basic", "read", "write"].map(Scope::from)))),
        }
    }
}