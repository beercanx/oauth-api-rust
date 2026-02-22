mod parser;

use serde::{Deserialize, Deserializer};

pub use parser::*;

#[derive(Eq, PartialEq, Debug)]
pub struct Scope {
    pub name: String,
}

// To enable us to trust Scope is valid, we don't allow direct deserialization of Scope.
impl<'de> Deserialize<'de> for Scope {
    fn deserialize< D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom("Scope deserialization not supported"))
    }
}

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
