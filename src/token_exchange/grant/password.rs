use crate::client::authentication::ClientAuthenticator;
use crate::client::{ClientPrincipal, ConfidentialClient, GrantType};
use crate::scope::parser::parse_scopes;
use crate::scope::Scopes;
use crate::token::repository::TokenRepository;
use crate::token::{AccessToken, TokenType};
use crate::token_exchange::response::{ErrorType, TokenExchangeResponse};
use crate::token_exchange::route::TokenExchangeState;
use crate::util::uuid_wrapper::UuidWrapper;
use crate::util::value_struct::ValueStruct;
use anyhow::Result;
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use ClientPrincipal::Confidential;
use GrantType::Password;

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
) -> Result<TokenExchangeResponse>
where
    A: TokenRepository<AccessToken>,
    C: ClientAuthenticator,
{

    // TODO - Implement it...
    
    let issued_at = Utc::now();

    let access_token = AccessToken {
        id: UuidWrapper::random(),
        username: request.username,
        client_id: request.principal.id().value().clone(),
        scopes: request.scopes.clone().map_or_else(String::new, |s|s.0.iter().map(ToString::to_string).collect::<Vec<String>>().join(" ")),
        issued_at: issued_at.naive_utc(),
        expires_at: (issued_at + Duration::hours(2)).naive_utc(),
        not_before: (issued_at - Duration::minutes(1)).naive_utc(),
    };

    state.access_token_repository.save_token(&access_token).await?;

    Ok(
        TokenExchangeResponse::Success {
            access_token: access_token.id,
            token_type: TokenType::Bearer,
            expires_in: 7200,
            refresh_token: Some(UuidWrapper::random()),
            scope: request.scopes,
            state: None,
        }
    )
}

pub fn validate_password_grant(principal: ClientPrincipal, request: &HashMap<String, String>) -> Result<PasswordGrantRequest, TokenExchangeResponse> {
    let client = match principal {
        Confidential(client) if client.can_perform_grant_type(&Password) => client,
        _ => Err(TokenExchangeResponse::Failure {
            error: ErrorType::UnauthorizedClient,
            error_description: Some(format!("not authorized to: {Password:?}")),
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
    use crate::client::configuration::ClientConfiguration;
    use crate::client::ClientType;
    use crate::map_of;
    use crate::scope::Scope;
    use crate::token_exchange::response::ErrorType;
    use assertables::*;
    use std::collections::HashSet;

    mod client {
        use super::*;
        use crate::client::configuration::{AllowedActions, AllowedGrantTypes, AllowedScopes, RedirectUris};

        #[test]
        fn should_return_invalid_request_for_a_public_client() {
            let result = validate_password_grant(
                ClientPrincipal::new_public_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "read write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::UnauthorizedClient,
                error_description: Some("not authorized to: Password".into())
            });
        }

        #[test]
        fn should_return_invalid_request_for_an_unauthorised_client() {
            let result = validate_password_grant(
                ClientPrincipal::new_principal(ClientConfiguration {
                    client_id: String::from("unauthorised").into(),
                    client_type: ClientType::Confidential,
                    redirect_uris: RedirectUris(HashSet::default()),
                    allowed_scopes: AllowedScopes(HashSet::default()),
                    allowed_actions: AllowedActions(HashSet::default()),
                    allowed_grant_types: AllowedGrantTypes(HashSet::default()),
                }),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "read write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::UnauthorizedClient,
                error_description: Some("not authorized to: Password".into())
            });
        }

        #[test]
        fn should_return_invalid_request_on_missing_username() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "password" => "<REDACTED>",
                    "scope" => "read write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidRequest,
                error_description: Some("missing parameter: username".into()),
            });
        }
    }

    mod username {
        use super::*;

        #[test]
        fn should_return_invalid_request_on_blank_username() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => " ",
                    "password" => "<REDACTED>",
                    "scope" => "read write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidRequest,
                error_description: Some("invalid parameter: username".into()),
            });
        }

        #[test]
        fn should_return_invalid_request_on_missing_password() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "scope" => "read write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidRequest,
                error_description: Some("missing parameter: password".into()),
            });
        }
    }

    mod scope {
        use super::*;
        use crate::client::configuration::{AllowedActions, AllowedGrantTypes, AllowedScopes, RedirectUris};

        #[test]
        fn should_return_invalid_request_on_blank_scope() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => " ",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            });
        }

        #[test]
        fn should_return_invalid_request_with_an_invalid_scope() {
            let result = validate_password_grant(
                ClientPrincipal::new_principal(ClientConfiguration {
                    client_id: String::from("aardvark").into(),
                    client_type: ClientType::Confidential,
                    redirect_uris: RedirectUris(HashSet::default()),
                    allowed_scopes: AllowedScopes(HashSet::default()),
                    allowed_actions: AllowedActions(HashSet::default()),
                    allowed_grant_types: AllowedGrantTypes(HashSet::from([Password])),
                }),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "invalid",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            });
        }

        #[test]
        fn should_return_invalid_request_with_an_invalid_scope_and_a_valid_scope() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! { "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "basic cicada",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            });
        }

        #[test]
        fn should_return_invalid_request_with_an_duplicated_valid_scopes() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "basic basic",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            });
        }

        #[test]
        fn should_return_invalid_request_with_an_unauthorised_scope() {
            let result = validate_password_grant(
                ClientPrincipal::new_principal(ClientConfiguration {
                    client_id: String::from("aardvark").into(),
                    client_type: ClientType::Confidential,
                    redirect_uris: RedirectUris(HashSet::default()),
                    allowed_scopes: AllowedScopes(HashSet::from([Scope::Read])),
                    allowed_actions: AllowedActions(HashSet::default()),
                    allowed_grant_types: AllowedGrantTypes(HashSet::from([Password])),
                }),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "write",
                },
            );

            let response = assert_err!(result);

            assert_eq!(response, TokenExchangeResponse::Failure {
                error: ErrorType::InvalidScope,
                error_description: Some("invalid parameter: scope".into()),
            });
        }
    }

    mod valid {
        use super::*;

        #[test]
        fn should_return_valid_request_if_only_scope_is_not_provided() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                },
            );

            let response = assert_ok!(result);

            assert_eq!(response, PasswordGrantRequest {
                principal: ClientPrincipal::new_confidential_client("aardvark"),
                username: "aardvark".into(),
                password: "<REDACTED>".into(),
                scopes: None,
            });
        }

        #[test]
        fn should_return_valid_request_if_only_one_scope_is_provided() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "basic",
                },
            );

            let response = assert_ok!(result);

            assert_eq!(response, PasswordGrantRequest {
                principal: ClientPrincipal::new_confidential_client("aardvark"),
                username: "aardvark".into(),
                password: "<REDACTED>".into(),
                scopes: Some(Scopes(HashSet::from([Scope::Basic]))),
            });
        }

        #[test]
        fn should_return_valid_request_if_multiple_scopes_are_provided() {
            let result = validate_password_grant(
                ClientPrincipal::new_confidential_principal("aardvark"),
                &map_of! {
                    "username" => "aardvark",
                    "password" => "<REDACTED>",
                    "scope" => "basic read write",
                },
            );

            let response = assert_ok!(result);

            assert_eq!(response, PasswordGrantRequest {
                principal: ClientPrincipal::new_confidential_client("aardvark"),
                username: "aardvark".into(),
                password: "<REDACTED>".into(),
                scopes: Some(Scopes(HashSet::from([Scope::Basic, Scope::Read, Scope::Write]))),
            });
        }
    }
}