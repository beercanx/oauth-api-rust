use serde::{Deserialize};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    Password,
}
