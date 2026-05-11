// @generated automatically by Diesel CLI.

diesel::table! {
    access_tokens (id) {
        id -> Binary,
        username -> Text,
        client_id -> Text,
        scopes -> Text,
        issued_at -> Timestamp,
        expires_at -> Timestamp,
        not_before -> Timestamp,
    }
}
