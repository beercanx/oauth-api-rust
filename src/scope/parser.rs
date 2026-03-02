use std::collections::HashSet;
use crate::scope::Scope;
use crate::scope::Scopes;

pub fn parse_scopes(maybe_space_delimited_scopes: Option<&String>) -> Result<Option<Scopes>, &str> {
    match maybe_space_delimited_scopes {
        Some(space_delimited_scopes) => {

            if space_delimited_scopes.is_empty() {
                return Err("defined but empty scopes");
            }

            let raw_scopes = space_delimited_scopes
                .split(" ")
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<String>>();

            if raw_scopes.is_empty() {
                return Err("defined but blank scopes");
            }

            let raw_scopes_count = raw_scopes.len();

            let scopes = raw_scopes
                .into_iter()
                .map(|scope| scope.parse::<Scope>())
                .filter(|scope| scope.is_ok())
                .map(|scope| scope.unwrap())
                .collect::<HashSet<Scope>>();

            if scopes.len() != raw_scopes_count {
                return Err("defined but invalid scope provided");
            }

            Ok(Some(Scopes(scopes)))
        },
        None => Ok(None)
    }
}
