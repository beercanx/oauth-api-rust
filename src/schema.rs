// @generated automatically by Diesel CLI.

diesel::table! {
    access_tokens (id) {
        id -> Binary,
        username -> Text,
        client_id -> Text,
        scopes -> Binary,
        issued_at -> Timestamp,
        expires_at -> Timestamp,
        not_before -> Timestamp,
    }
}

diesel::table! {
    client_configurations (client_id) {
        client_id -> Text,
        client_type -> Text,
        redirect_uris -> Binary,
        allowed_scopes -> Binary,
        allowed_actions -> Binary,
        allowed_grant_types -> Binary,
    }
}

diesel::joinable!(access_tokens -> client_configurations (client_id));

diesel::allow_tables_to_appear_in_same_query!(access_tokens, client_configurations,);
