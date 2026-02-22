use axum::extract::State;
use axum::http::StatusCode;
use axum::Router;
use axum::routing::post;
use axum::response::Json;
use crate::token::{AccessToken, TokenRepository};
use crate::token_exchange::grant::handle_password_grant;
use crate::token_exchange::response::TokenExchangeResponse;
use crate::token_exchange::response::ErrorType::UnsupportedGrantType;
use crate::token_exchange::request::{TokenExchangeForm, TokenExchangeRequest};

// https://www.rfc-editor.org/rfc/rfc6749#section-3.2
pub fn route<A>(state: TokenExchangeState<A>) -> Router<()>
where
    A: TokenRepository<AccessToken> + 'static
{
    Router::new()
        .route("/token", post(token_exchange_handler))
        .with_state(state)
}

#[derive(Clone)]
pub struct TokenExchangeState<A: TokenRepository<AccessToken>> {
    pub access_token_repository: A,
}

async fn token_exchange_handler<A: TokenRepository<AccessToken>>(
    State(state): State<TokenExchangeState<A>>,
    TokenExchangeForm(request): TokenExchangeForm,
) -> (StatusCode, Json<TokenExchangeResponse>) {

    // TODO - Handle client principal

    let result = match request {
        TokenExchangeRequest::AuthorizationCode(_) => TokenExchangeResponse::Failure { // TODO - Implement
            error: UnsupportedGrantType,
            error_description: Some("unsupported grant type: authorization_code".into())
        },
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

    use axum::body::Body;
    use axum::http::{Method, Request, Response};
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use serde_json::Value;
    use tower::ServiceExt;

    // See: https://github.com/beercanx/oauth-api/blob/main/api/token/src/test/kotlin/uk/co/baconi/oauth/api/token/TokenRouteIntegrationTests.kt

    const TOKEN_ENDPOINT: &str = "/token";
    const X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
    const TEST_CLIENT_PASSWORD: &'static str = "9VylF3DbEeJbtdbih3lqpNXBw@Non#bi";

    macro_rules! under_test {
        () => {
            route(TokenExchangeState {
                access_token_repository: crate::token::InMemoryTokenRepository::new(),
            })
        };
    }

    async fn extract_json_body(response: Response<Body>) -> HashMap<String, Value> {
        serde_json::from_slice(response.into_body().collect().await.unwrap().to_bytes().as_ref()).unwrap()
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
        #[ignore = "client authentication not yet implemented"] // TODO - Re-enable once client authentication is implemented
        async fn should_require_client_authentication() {
            let router = under_test!();

            let request = Request::builder()
                .method(Method::POST)
                .uri(TOKEN_ENDPOINT)
                .header("Content-Type", X_WWW_FORM_URLENCODED)
                .body(Body::from("grant_type=password&username=u&password=p&scope=basic"))
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
                        .header("Content-Type", format!("application/{content_type}"))
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
                .header("Content-Type", X_WWW_FORM_URLENCODED)
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
        use assertables::{assert_none, assert_some, assert_some_eq_x};
        use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
        use base64::prelude::*;
        use super::*;

        fn basic_auth(username: &str, password: &str) -> String {
            format!("Basic {}", BASE64_STANDARD.encode(format!("{}:{}", username, password)))
        }

        #[tokio::test]
        async fn should_return_ok_for_valid_password_grants() {
            let router = under_test!();

            let request = Request::builder()
            .method(Method::POST)
            .uri(TOKEN_ENDPOINT)
            .header(AUTHORIZATION, basic_auth("confidential-cicada", TEST_CLIENT_PASSWORD))
            .header(CONTENT_TYPE, X_WWW_FORM_URLENCODED)
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
                .header(AUTHORIZATION, basic_auth("confidential-cicada", TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, X_WWW_FORM_URLENCODED)
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
                .header(AUTHORIZATION, basic_auth("confidential-cicada", TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, X_WWW_FORM_URLENCODED)
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
                .header(AUTHORIZATION, basic_auth("confidential-cicada", TEST_CLIENT_PASSWORD))
                .header(CONTENT_TYPE, X_WWW_FORM_URLENCODED)
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