use serde::Serialize;
use crate::client::ClientId;
use crate::token::TokenType;

#[cfg_attr(test, derive(Debug))]
#[derive(Serialize)]
#[serde(untagged)]
pub enum TokenIntrospectionResponse {
    Active {
        /**
         * Boolean indicator of whether the presented token is currently active.
         *
         * The specifics of a token's "active" state will vary depending on the implementation of
         * the authorization server and the information it keeps about its tokens, but a "true"
         * value return for the "active" property will generally indicate that a given token has
         * been issued by this authorization server, has not been revoked by the resource owner,
         * and is within its given time window of validity (e.g., after its issuance time and before
         * its expiration time).
         *
         * See Section 4 for information on implementation of such checks <https://www.rfc-editor.org/rfc/rfc7662#section-4>.
         */
        active: bool,

        /**
         * A JSON string containing a space-separated list of scopes associated with this token,
         * in the format described in Section 3.3 of OAuth 2.0 <https://www.rfc-editor.org/rfc/rfc6749#section-3.3>.
         */
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>, // TODO - Use an internal type and setup serialization for it.

        /**
         * Client identifier for the OAuth 2.0 client that requested this token.
         */
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<ClientId>,

        /**
         * Human-readable identifier for the resource owner who authorized this token.
         */
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>, // TODO - Use an internal value struct AuthenticatedUsername

        /**
         * Type of the token as defined in Section 5.1 of OAuth 2.0 <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>.
         */
        #[serde(skip_serializing_if = "Option::is_none")]
        token_type: Option<TokenType>,

        /**
         * Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token will expire, as defined in JWT <https://www.rfc-editor.org/rfc/rfc7519>
         */
        #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
        expires_at: Option<i64>,

        /**
         * Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token was originally issued, as defined in JWT <https://www.rfc-editor.org/rfc/rfc7519>
         */
        #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
        issued_at: Option<i64>,

        /**
         * Integer timestamp, measured in the number of seconds since January 1 1970 UTC,
         * indicating when this token is not to be used before, as defined in JWT <https://www.rfc-editor.org/rfc/rfc7519>
         */
        #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
        not_before: Option<i64>,

    },
    Inactive {
        /**
         * Boolean indicator of whether the presented token is currently active.
         */
        active: bool,
    },
    Invalid {
        /**
         * A single ASCII error code from the defined list.
         */
        error: ErrorType,

        /**
         * Human-readable ASCII text providing additional information, used
         * to assist the client developer in understanding the error that occurred.
         */
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
    },
}

#[cfg_attr(test, derive(Debug))]
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidRequest,
    //UnauthorizedClient,
}

impl TokenIntrospectionResponse {
    pub fn missing_parameter(parameter: &str) -> Self {
        TokenIntrospectionResponse::Invalid {
            error: ErrorType::InvalidRequest,
            error_description: Some(format!("missing parameter: {parameter}")),
        }
    }

    pub fn invalid_parameter(parameter: &str) -> Self {
        TokenIntrospectionResponse::Invalid {
            error: ErrorType::InvalidRequest,
            error_description: Some(format!("invalid parameter: {parameter}")),
        }
    }
}