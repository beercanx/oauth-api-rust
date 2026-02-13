use serde::Serialize;
use crate::token::TokenType;

#[derive(Serialize)]
#[serde(untagged)]
pub enum TokenExchangeResponse {

    Success {

        // The access token issued by the authorization server.
        access_token: uuid::Uuid,

        // The type of the token issued as described in
        // https://www.rfc-editor.org/rfc/rfc6749#section-7.1
        token_type: TokenType,

        // The lifetime in seconds of the access token. For example, the value
        // "3600" denotes that the access token will expire in one hour from the time the
        // response was generated. If omitted, the authorization server SHOULD provide
        // the expiration time via other means or document the default value.
        expires_in: i64,

        // OPTIONAL. The refresh token, which can be used to obtain new
        // access tokens using the same authorization grant as described in
        // https://www.rfc-editor.org/rfc/rfc6749#section-6
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<uuid::Uuid>,

        // OPTIONAL if identical to the scope requested by the client; otherwise,
        // REQUIRED. The scope of the access token as described by
        // https://www.rfc-editor.org/rfc/rfc6749#section-3.3
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,

        // State REQUIRED if the "state" parameter was present in the client
        // authorization request. The exact value received from the client.
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<String>,
    },

    Failure {

        // A single ASCII error code from the defined list.
        error: ErrorType,

        // Description Human-readable ASCII text providing additional information, used
        // to assist the client developer in understanding the error that occurred.
        error_description: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {

    // The request is missing a required parameter, includes an
    // unsupported parameter value (other than a grant type), repeats a parameter,
    // includes multiple credentials, uses more than one mechanism for
    // authenticating the client, or is otherwise malformed.
    InvalidRequest,

    // Client authentication failed (e.g., unknown client, no client
    // authentication included, or unsupported authentication method). The
    // authorization server MAY return an HTTP 401 (Unauthorized) status code to
    // indicate which HTTP authentication schemes are supported. If the client
    // attempted to authenticate via the "Authorization" request header field, the
    // authorization server MUST respond with an HTTP 401 (Unauthorized) status code
    // and include the "WWW-Authenticate" response header field matching the
    // authentication scheme used by the client.
    InvalidClient,

    // The provided authorization grant (e.g., authorization code,
    // resource owner credentials) or refresh token is invalid, expired, revoked,
    // does not match the redirection URI used in the authorization request, or was
    // issued to another client.
    InvalidGrant,

    // The requested scope is invalid, unknown, malformed, or exceeds
    // the scope granted by the resource owner.
    InvalidScope,

    // The authenticated client is not authorized to use this
    // authorization grant type.
    UnauthorizedClient,

    // The authorization grant type is not supported by the
    // authorization server.
    UnsupportedGrantType,
}
