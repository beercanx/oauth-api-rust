use axum::Extension;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use crate::client::{ClientAction, ConfidentialClient};

pub async fn require_confidential_client_action(
    Extension(client): Extension<ConfidentialClient>,
    State(action): State<ClientAction>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if client.can_perform_action(&action) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::FORBIDDEN) // TODO - Return { error: "unauthorized_client", error_description: "Client is not authorized to perform this action" }
    }
}
