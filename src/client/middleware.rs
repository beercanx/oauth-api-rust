use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Basic;
use axum_extra::TypedHeader;
use crate::client::authentication::ClientAuthenticator;
use crate::client::ClientPrincipal;

pub async fn require_confidential_client_authentication<C: ClientAuthenticator>(
    State(authenticator): State<C>,
    maybe_basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {

    let client = match maybe_basic_auth {
        None => return Err(StatusCode::UNAUTHORIZED),
        Some(TypedHeader(Authorization(basic))) => {
            authenticator.authenticate_as_confidential_client(basic.username(), basic.password().as_bytes()).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::UNAUTHORIZED)?
        },
    };

    request.extensions_mut().insert(client);

    Ok(next.run(request).await)
}

pub async fn require_client_authentication<C: ClientAuthenticator>(
    State(authenticator): State<C>,
    maybe_basic_auth: Option<TypedHeader<Authorization<Basic>>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {

    // Split the request into parts so we can rebuild it later.
    let (parts, body) = request.into_parts();

    // Buffer the body to peek at client_id
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look for client_id in the body.
    let maybe_client_id = form_urlencoded::parse(&body_bytes)
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned());

    let principal = match (maybe_basic_auth, maybe_client_id) {
        // Both are present → reject per RFC 6749 §2.3
        (Some(_), Some(_)) => return Err(StatusCode::UNAUTHORIZED),

        // Neither is present → reject
        (None, None) => return Err(StatusCode::UNAUTHORIZED),

        // Confidential client via Basic auth
        (Some(TypedHeader(Authorization(basic))), None) => {
            authenticator.authenticate_as_confidential_client(basic.username(), basic.password().as_bytes()).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .map(ClientPrincipal::Confidential)
        },

        // Public client via body client_id
        (None, Some(client_id)) => {
            authenticator.authenticate_as_public_client(&client_id).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .map(ClientPrincipal::Public)
        },
    };

    match principal {
        None => Err(StatusCode::UNAUTHORIZED),
        Some(client_principal) => {
            let mut new_request = Request::from_parts(parts, Body::from(body_bytes));
            new_request.extensions_mut().insert(client_principal);
            Ok(next.run(new_request).await)
        }
    }
}
