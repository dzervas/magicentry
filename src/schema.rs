// @generated automatically by Diesel CLI.

diesel::table! {
    config (key) {
        key -> Text,
        value -> Nullable<Text>,
    }
}

diesel::table! {
    sessions (id) {
        id -> Nullable<Integer>,
        session_id -> Text,
        email -> Text,
        expires_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    config,
    sessions,
);
