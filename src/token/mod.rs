mod repository;

pub use repository::*;

use serde::Serialize;
use uuid::Uuid;

pub trait Token {
    fn id(&self) -> Uuid;
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}

#[derive(Serialize, Debug, Clone)]
pub struct AccessToken {
    pub id: Uuid
}

impl Token for AccessToken {
    fn id(&self) -> Uuid {
        self.id
    }
}
