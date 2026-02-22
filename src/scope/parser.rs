use crate::scope::Scope;

// TODO - Extract into config
const VALID_SCOPES: [&str; 3] = ["basic", "read", "write"];
fn is_valid_scope(scope: &str) -> bool {
    VALID_SCOPES.contains(&scope)
}

pub fn parse_scopes(maybe_space_delimited_scopes: Option<&String>) -> Result<Option<Vec<Scope>>, &str> {
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
                .filter(|scope| is_valid_scope(scope))
                .map(Scope::from)
                .collect::<Vec<Scope>>();

            if scopes.len() != raw_scopes_count {
                return Err("defined but invalid scope provided");
            }

            Ok(Some(scopes))
        },
        None => Ok(None)
    }
}
