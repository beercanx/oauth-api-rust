pub mod parser;

use crate::disable_deserialization;
use serde::{Serialize, Serializer};
use std::collections::HashSet;
use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::EnumString;

#[derive(EnumString, EnumIter, Display, Debug, Hash, Eq, PartialEq, Clone)]
#[strum(serialize_all = "snake_case")]
pub enum Scope {
    Basic,
    Read,
    Write,
}

#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Scopes(pub HashSet<Scope>);

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
disable_deserialization!(Scope);
disable_deserialization!(Scopes);
