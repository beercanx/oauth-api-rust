pub mod repository;

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Serialize;
use crate::util::uuid_wrapper::UuidWrapper;

#[cfg_attr(test, derive(Debug))]
#[derive(Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}

#[derive(Serialize, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = crate::schema::access_tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct AccessToken {
    pub id: UuidWrapper,
    pub username: String,                   // TODO - Use AuthenticatedUser
    pub client_id: String,                  // TODO - Use ClientId
    pub scopes: String,                     // TODO - Use Scopes
    pub issued_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub not_before: NaiveDateTime,
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use chrono::Utc;
    impl AccessToken {
        pub fn new() -> AccessToken {
            AccessToken {
                id: UuidWrapper::random(),
                username: "aardvark".to_string(),
                client_id: "badger".to_string(),
                scopes: "basic".to_string(),
                issued_at: Utc::now().naive_utc(),
                expires_at: Utc::now().naive_utc(),
                not_before: Utc::now().naive_utc(),
            }
        }
    }
}