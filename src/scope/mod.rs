mod parser;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub use parser::*;

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Scope {
    pub name: String,
}

#[derive(Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Scopes(pub Vec<Scope>);

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
impl<'de> Deserialize<'de> for Scope {
    fn deserialize< D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom("Scope deserialization not supported"))
    }
}

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize< D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom("Scopes deserialization not supported"))
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
