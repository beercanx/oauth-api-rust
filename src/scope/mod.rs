pub mod parser;

use std::collections::HashSet;
use serde::{Serialize, Serializer};
use crate::disable_deserialization;

#[derive(Hash, Eq, PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Scope { // TODO - Rework into value_struct! ???
    pub name: String,
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Scopes(pub HashSet<Scope>);

impl Serialize for Scopes {
    // Serialize scopes as a space delimited list
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.iter()
            .map(|scope| scope.name.clone())
            .collect::<Vec<String>>()
            .join(" ")
            .serialize(serializer)
    }
}

// To enable us to trust Scope is valid, we don't allow direct deserialization of Scope.
disable_deserialization!(Scope);
disable_deserialization!(Scopes);

impl From<String> for Scope {
    fn from(name: String) -> Self {
        Scope { name }
    }
}

impl From<&str> for Scope {
    fn from(name: &str) -> Self {
        Scope { name: name.into() }
    }
}

impl From<&String> for Scope {
    fn from(name: &String) -> Self {
        Scope { name: name.clone() }
    }
}
