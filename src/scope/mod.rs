pub mod parser;

use crate::{diesel_from_sql_for_json_fields, diesel_to_sql_for_json_fields, disable_deserialization};
use diesel::{AsExpression, FromSqlRow};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashSet;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;

#[derive(EnumString, EnumIter, Display, Serialize, Deserialize, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Basic,
    Read,
    Write,
}

#[derive(FromSqlRow, AsExpression, Default, Debug, Eq, PartialEq, Clone)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct Scopes(pub HashSet<Scope>);

diesel_from_sql_for_json_fields! {
    Scopes(HashSet<Scope>);
}

diesel_to_sql_for_json_fields! {
    Scopes(HashSet<Scope>);
}

impl Serialize for Scopes {
    // Serialize scopes as a space delimited list
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(" ")
            .serialize(serializer)
    }
}

// To enable us to trust Scope is valid, we don't allow direct deserialization of Scope.
disable_deserialization!(Scopes);
