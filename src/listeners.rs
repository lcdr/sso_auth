//! Message listeners responsible for the behavior of the server in response to incoming messages.
use diesel::prelude::*;
use lu_packets::auth::{
	client::{LoginResponse, Message as OutMessage},
	server::{LoginRequest, Message as IncMessage},
};
use lu_packets::common::ServiceId;

use base_server::listeners::{on_conn_req, on_handshake, on_internal_ping};

use base_server::server::Context as C;
use crate::models::User;
type Context = C<IncMessage, OutMessage>;

/// Keeps track of the DB connection.
pub struct MsgCallback {
	/// Connection to the users DB.
	conn: SqliteConnection,
}

impl MsgCallback {
	/// Creates a new callback connecting to the DB at the provided path.
	pub fn new(db_path: &str) -> Self {
		let conn = SqliteConnection::establish(db_path).unwrap();
		Self { conn }
	}

	/// Dispatches to the various handlers depending on message type.
	pub fn on_msg(&self, msg: &IncMessage, ctx: &mut Context) {
		use lu_packets::auth::server::{
			Message::{InternalPing, ConnectionRequest, NewIncomingConnection, UserMessage},
			LUMessage::{General, Auth},
			GeneralMessage::Handshake,
			AuthMessage::LoginRequest,
		};
		dbg!(&msg);
		match msg {
			InternalPing(msg)                    => on_internal_ping(msg, ctx),
			ConnectionRequest(msg)               => on_conn_req(msg, ctx),
			NewIncomingConnection(msg)           => { dbg!(msg); },
			UserMessage(General(Handshake(msg))) => on_handshake(msg, ctx, ServiceId::Auth),
			UserMessage(Auth(LoginRequest(msg))) => self.on_login_req(msg, ctx),
			_ => { println!("Unrecognized packet: {:?}", msg); },
		}
	}

	/**
		Responds to login requests.

		Looks up username and hashed password in the DB, responding with an error if they don't match.
		If they match, generates a new session key and saves it to the DB, then responds with the key as well as the redirect address from the DB.
	*/
	fn on_login_req(&self, event: &LoginRequest, ctx: &mut Context) {
		use crate::schema::users::dsl::{users, username, session_key};

		let user = match users.filter(username.eq(String::from(&event.username))).first::<User>(&self.conn) {
			Err(_) => {
				println!("Login attempt with unknown username {}", String::from(&event.username));
				ctx.send(LoginResponse::InvalidUsernamePassword).unwrap();
				return;
			}
			Ok(x) => x,
		};

		if !bcrypt::verify(String::from(&event.password), &user.password).unwrap() {
			println!("Login attempt with username {} and invalid password", user.username);
			ctx.send(LoginResponse::InvalidUsernamePassword).unwrap();
			return;
		}

		let new_session_key: u128 = rand::random();
		let new_session_key = format!("{:032x}", new_session_key);

		println!("Logging in {} to ({}, {}) with key {}", user.username, user.redirect_host, user.redirect_port, user.session_key);

		diesel::update(users.find(user.id)).set(session_key.eq(&new_session_key)).execute(&self.conn).unwrap();

		let redirect_address = (user.redirect_host[..].into(), user.redirect_port as u16);
		let message = LoginResponse::Ok {
			session_key: new_session_key[..].into(),
			redirect_address,
		};
		ctx.send(message).unwrap();
	}
}
