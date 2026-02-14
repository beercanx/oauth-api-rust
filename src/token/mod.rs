mod repository;

use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}

#[derive(Serialize, Debug, Clone)]
pub struct AccessToken {
    id: Uuid
}
