// @generated automatically by Diesel CLI.

diesel::table! {
    config (key) {
        key -> Text,
        value -> Nullable<Text>,
    }
}

diesel::table! {
    links (magic) {
        magic -> Text,
        email -> Text,
        expires_at -> Timestamp,
    }
}

diesel::table! {
    sessions (session_id) {
        session_id -> Text,
        email -> Text,
        expires_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    config,
    links,
    sessions,
);
