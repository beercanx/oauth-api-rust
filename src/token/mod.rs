pub mod repository;
#[cfg(feature = "diesel")]
mod schema;

use serde::Serialize;
use crate::util::uuid_wrapper::UuidWrapper;

pub trait Token: Send + Sync + Clone {
    fn id(&self) -> UuidWrapper;
}

#[cfg_attr(test, derive(Debug))]
#[derive(Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}

#[derive(Serialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "diesel", derive(diesel::Queryable, diesel::Selectable, diesel::Insertable))]
#[cfg_attr(feature = "diesel", diesel(table_name = schema::access_tokens))]
#[cfg_attr(feature = "diesel", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct AccessToken {
    pub id: UuidWrapper,
    pub username: String,                   // TODO - Use AuthenticatedUser
    pub client_id: String,                  // TODO - Use ClientId
    pub scopes: String,                     // TODO - Use Scopes
    pub issued_at: chrono::NaiveDateTime,
    pub expires_at: chrono::NaiveDateTime,
    pub not_before: chrono::NaiveDateTime,
}

impl Token for AccessToken {
    fn id(&self) -> UuidWrapper {
        self.id
    }
}
