pub mod parser;

use std::collections::HashSet;
use serde::{Serialize, Serializer};
use crate::disable_deserialization;
use crate::enum_with_from_str;

enum_with_from_str! {
    #[derive(Hash, Eq, PartialEq, Clone)]
    #[cfg_attr(test, derive(Debug))]
    pub enum Scope {
        Basic: "basic",
        Read: "read",
        Write: "write",
    }
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Scopes(pub HashSet<Scope>);

impl Serialize for Scopes {
    // Serialize scopes as a space delimited list
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<String>>()
            .join(" ")
            .serialize(serializer)
    }
}

// To enable us to trust Scope is valid, we don't allow direct deserialization of Scope.
disable_deserialization!(Scope);
disable_deserialization!(Scopes);
