//! Database models.
use diesel::Queryable;

/// A user in the database.
#[derive(Debug)]
#[derive(Queryable)]
pub struct User {
	/// Unique ID.
	pub id: i32,
	/// Username used for logging in.
	pub username: String,
	/// Password used for logging in.
	pub password: String,
	/// Domain or IP of the world server the auth server should redirect to on successful login.
	pub redirect_host: String,
	/// Port of the world server the auth server should redirect to on successful login.
	pub redirect_port: i32,
	/// The token the auth server hands out to clients on successful login, to be used by world servers to verify a logged in user without needing a password.
	pub session_key: String,
}
