diesel::table! {
    access_tokens (id) {
        id -> Text, // TODO - Convert to UUID via DB converters
        client_id -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}
