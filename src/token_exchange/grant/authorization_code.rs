use serde::Deserialize;

#[derive(Deserialize)]
pub struct AuthorizationCodeGrantRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}
