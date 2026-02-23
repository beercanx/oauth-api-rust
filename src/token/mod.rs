pub mod repository;

use serde::Serialize;
use uuid::Uuid;

pub trait Token {
    fn id(&self) -> Uuid;
}

#[cfg_attr(test, derive(Debug))]
#[derive(Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}

#[derive(Serialize, Clone)]
pub struct AccessToken {
    pub id: Uuid
}

impl Token for AccessToken {
    fn id(&self) -> Uuid {
        self.id
    }
}
