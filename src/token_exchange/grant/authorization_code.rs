use serde::Deserialize;

#[derive(Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct AuthorizationCodeGrantRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}
