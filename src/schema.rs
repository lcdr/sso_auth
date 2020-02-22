table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
        redirect_host -> Text,
        redirect_port -> Integer,
        session_key -> Text,
    }
}
