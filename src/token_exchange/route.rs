use axum::extract::State;
use axum::http::StatusCode;
use axum::{middleware, Router};
use axum::routing::post;
use axum::response::Json;
use middleware::from_fn_with_state;
use crate::client::authentication::ClientAuthenticator;
use crate::client::middleware::require_client_authentication;
use crate::token::AccessToken;
use crate::token::repository::TokenRepository;
use crate::token_exchange::grant::password::handle_password_grant;
use crate::token_exchange::response::TokenExchangeResponse;
use crate::token_exchange::request::{TokenExchangeForm, TokenExchangeRequest};

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
pub fn route<A, C>(state: TokenExchangeState<A, C>) -> Router<()>
where
    A: TokenRepository<AccessToken> + 'static,
    C: ClientAuthenticator + 'static,
{
    Router::new()
        .route("/token", post(token_exchange_handler))
        .route_layer(from_fn_with_state(state.client_authenticator.clone(), require_client_authentication::<C>))
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenExchangeState<A: TokenRepository<AccessToken>, C: ClientAuthenticator> {
    pub access_token_repository: A,
    pub client_authenticator: C
}

async fn token_exchange_handler<A: TokenRepository<AccessToken>, C: ClientAuthenticator>(
    State(state): State<TokenExchangeState<A, C>>,
    TokenExchangeForm(request): TokenExchangeForm,
) -> (StatusCode, Json<TokenExchangeResponse>) {

    let result = match request {
        TokenExchangeRequest::Password(password_grant_request) => {
            handle_password_grant(state, password_grant_request).await
        },
    };

    let status = match result {
        TokenExchangeResponse::Failure { .. } => StatusCode::BAD_REQUEST,
        TokenExchangeResponse::Success { .. } => StatusCode::OK,
    };

    (status, Json(result))
}

#[cfg(test)]
mod integration_tests {

    use super::*;

    use assertables::*;
    use axum::body::Body;
    use axum::http::{Method, Request, Response};
    use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use base64::prelude::*;
    use serde_json::Value;
    use tower::ServiceExt;

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/TokenRouteIntegrationTests.kt

    const TOKEN_ENDPOINT: &str = "/token";
    const APPLICATION_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
    const TEST_CLIENT_USERNAME: &'static str = "aardvark";
    const TEST_CLIENT_PASSWORD: &'static str = "badger";

    macro_rules! under_test {
        () => {
            route(TokenExchangeState {
                access_token_repository: crate::token::repository::InMemoryTokenRepository::new(),
                client_authenticator: crate::client::authentication::ClientAuthenticationService::new(
                    crate::client::secret::InMemoryClientSecretRepository::new(),
                    crate::client::configuration::InMemoryClientConfigurationRepository::new(),
                ),
            })
        };
    }

    async fn extract_json_body(response: Response<Body>) -> HashMap<String, Value> {
        serde_json::from_slice(response.into_body().collect().await.unwrap().to_bytes().as_ref()).unwrap()
    }

    fn basic_auth(username: &str, password: &str) -> String {
        format!("Basic {}", BASE64_STANDARD.encode(format!("{}:{}", username, password)))
    }

    mod invalid_http_request {
        use super::*;

        macro_rules! http_method_test {
            ($($name:ident: $method:expr,)*) => {
            $(
                #[tokio::test]
                async fn $name() {
                    let router = under_test!();

                    let request = Request::builder()
                        .method($method)
                        .uri(TOKEN_ENDPOINT)
                        .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                        .body(Body::empty())
                        .unwrap();

                    let response = router.oneshot(request).await.unwrap();

                    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
                }
            )*
            }
        }

        http_method_test! {
            should_not_support_http_method_get: Method::GET,
            should_not_support_http_method_put: Method::PUT,
            should_not_support_http_method_patch: Method::PATCH,
            should_not_support_http_method_delete: Method::DELETE,
            should_not_support_http_method_head: Method::HEAD,
            should_not_support_http_method_options: Method::OPTIONS,
            should_not_support_http_method_trace: Method::TRACE,
            should_not_support_http_method_connect: Method::CONNECT,
        }

        #[tokio::test]
        async fn should_require_client_authentication_on_missing_authorization_header() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header("Content-Type", APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from("grant_type=password&username=u&password=<REDACTED>&scope=basic"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn should_require_client_authentication_on_invalid_confidential_client_credentials() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .header(AUTHORIZATION, basic_auth("invalid", "<REDACTED>"))
                .body(Body::from("grant_type=password&username=u&password=<REDACTED>&scope=basic"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn should_require_client_authentication_on_invalid_public_client_credentials() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from("grant_type=password&username=u&password=<REDACTED>&scope=basic&client_id=invalid"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn should_require_client_authentication_via_only_one_method() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .body(Body::from("grant_type=password&username=u&password=<REDACTED>&scope=basic&client_id=badger"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        macro_rules! content_type_test {
            ($($name:ident: $value:expr,)*) => {
            $(
                #[tokio::test]
                async fn $name() {
                    let router = under_test!();

                    let (content_type, body) = $value;

                    let request = Request::builder()
                        .method(Method::POST)
                        .uri(TOKEN_ENDPOINT)
                        .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                        .header(CONTENT_TYPE, format!("application/{content_type}"))
                        .body(Body::from(body))
                        .unwrap();

                    let response = router.oneshot(request).await.unwrap();

                    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
            )*
            }
        }

        content_type_test! {
            should_not_support_application_xml: ("xml", r#"<grantType>aardvark</grantType>"#),
            should_not_support_application_json: ("json", r#"{"grant_type":"aardvark"}"#),
        }
    }

    mod invalid_token_request {
        use super::*;

        #[tokio::test]
        async fn should_return_bad_request_for_invalid_token_exchange_requests() {

            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from("grant_type=aardvark"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let body = extract_json_body(response).await;
            assert_eq!(body["error"], "unsupported_grant_type");
            assert_eq!(body["error_description"], "unsupported: aardvark");
        }

    }

    mod success_token_request {
        use super::*;

        #[tokio::test]
        async fn should_return_ok_for_valid_password_grants() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from("grant_type=password&username=aardvark&password=badger&scope=basic"))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = extract_json_body(response).await;
            assert_some!(body.get("access_token"));
            assert_some!(body.get("refresh_token"));
            assert_some_eq_x!(body.get("token_type"), "bearer");
            assert_some_eq_x!(body.get("expires_in"), 7200);
            assert_some_eq_x!(body.get("scope"), "basic");
            assert_none!(body.get("state"));
        }

        #[tokio::test]
        #[ignore = "authorization code not yet implemented"] // TODO - Re-enable once implemented
        async fn should_return_ok_for_valid_authorization_code_grants() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from(format!("grant_type=authorization_code&code={}&scope=basic&redirect_uri=https%3A%2F%2Fredirect.baconi.co.uk", uuid::Uuid::new_v4())))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = extract_json_body(response).await;
            assert_some!(body.get("access_token"));
            assert_some!(body.get("refresh_token"));
            assert_some_eq_x!(body.get("token_type"), "bearer");
            assert_some_eq_x!(body.get("expires_in"), 7200);
            assert_some_eq_x!(body.get("scope"), "basic");
        }

        #[tokio::test]
        #[ignore = "refresh grant not yet implemented"] // TODO - Re-enable once implemented
        async fn should_return_ok_for_valid_refresh_token_grant() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from(format!("grant_type=refresh_token&refresh_token={}&scope=basic", uuid::Uuid::new_v4())))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = extract_json_body(response).await;
            assert_some!(body.get("access_token"));
            assert_some!(body.get("refresh_token"));
            assert_some_eq_x!(body.get("token_type"), "bearer");
            assert_some_eq_x!(body.get("expires_in"), 7200);
            assert_some_eq_x!(body.get("scope"), "basic");
        }

        #[tokio::test]
        #[ignore = "assertion grant not yet implemented"] // TODO - Re-enable once implemented
        async fn should_return_ok_for_valid_assertion_grant() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header(AUTHORIZATION, basic_auth(TEST_CLIENT_USERNAME, TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, APPLICATION_WWW_FORM_URLENCODED)
                .body(Body::from(format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}", uuid::Uuid::new_v4())))
                .unwrap();

            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = extract_json_body(response).await;
            assert_some!(body.get("access_token"));
            assert_some!(body.get("refresh_token"));
            assert_some_eq_x!(body.get("token_type"), "bearer");
            assert_some_eq_x!(body.get("expires_in"), 7200);
            assert_some_eq_x!(body.get("scope"), "basic");
        }
    }
}