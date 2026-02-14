use crate::token::TokenType;
use crate::token_exchange::request::PasswordGrantRequest;
use crate::token_exchange::response::TokenExchangeResponse;

pub async fn handle_password_grant(request: PasswordGrantRequest) -> TokenExchangeResponse {

    println!("handle_password_grant({request:?})");

    // TODO - Implement it...

    TokenExchangeResponse::Success {
        access_token: uuid::Uuid::new_v4(),
        token_type: TokenType::Bearer,
        expires_in: 7200,
        refresh_token: Some(uuid::Uuid::new_v4()),
        scope: request.scope,
        state: None,
    }
}
