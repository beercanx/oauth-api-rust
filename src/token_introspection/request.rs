use std::collections::HashMap;
use axum::extract::{FromRequest, Request};
use axum::extract::rejection::FormRejection;
use axum::{Form, Json};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;
use crate::token_introspection::response::{ErrorType, TokenIntrospectionResponse};

pub struct TokenIntrospectionRequest {
    pub(crate) token: Uuid,
}

pub struct TokenIntrospectionForm(pub TokenIntrospectionRequest);

impl<S: Send + Sync> FromRequest<S> for TokenIntrospectionForm {
    type Rejection = Response;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Form::<HashMap<String, String>>::from_request(req, state).await {
            Err(rejection) => Err(handle_form_rejection(rejection)),
            Ok(Form(request)) => match validate_request(request) {
                Err(failure) => Err(handle_validation_failure(failure)),
                Ok(valid) => Ok(valid),
            }
        }
    }
}

fn validate_request(request: HashMap<String, String>) -> Result<TokenIntrospectionForm, TokenIntrospectionResponse> {
    match request.get("token").map(|s| Uuid::parse_str(s)) {
        None => Err(TokenIntrospectionResponse::missing_parameter("token")),
        Some(Err(_)) => Err(TokenIntrospectionResponse::invalid_parameter("token")),
        Some(Ok(token)) => Ok(TokenIntrospectionForm(TokenIntrospectionRequest { token })),
    }
}

fn handle_validation_failure(failure: TokenIntrospectionResponse) -> Response {
    (StatusCode::BAD_REQUEST, Json(failure)).into_response()
}

fn handle_form_rejection(rejection: FormRejection) -> Response {
    (rejection.status(), Json(TokenIntrospectionResponse::Invalid {
        error: ErrorType::InvalidRequest,
        error_description: Some(rejection.body_text()),
    })).into_response()
}