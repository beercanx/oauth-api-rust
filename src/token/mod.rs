use serde::Serialize;

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    // https://www.rfc-editor.org/rfc/rfc6750
    Bearer,
}
