//! Message listeners responsible for the behavior of the server in response to incoming messages.
use std::net::{IpAddr, Ipv4Addr};

use diesel::prelude::*;
use lu_packets::{
	common::ServiceId,
	auth_client::{LoginResponse, Message as OutMessage, Handshake as OutHandshake},
	auth_server::{ConnectionRequest, InternalPing, LoginRequest, Message as IncMessage, Handshake as IncHandshake},
};

use crate::models::User;
use crate::auth::Context as C;
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
		use lu_packets::auth_server::{
			Message::{InternalPing, ConnectionRequest, UserMessage},
			LUMessage::{General, Auth},
			GeneralMessage::Handshake,
			AuthMessage::LoginRequest,
		};

		match msg {
			InternalPing(msg)                    => on_internal_ping(msg, ctx),
			ConnectionRequest(msg)               => on_conn_req(msg, ctx),
			UserMessage(General(Handshake(msg))) => on_handshake(msg, ctx),
			UserMessage(Auth(LoginRequest(msg))) => self.on_login_req(msg, ctx),
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

/// Sends back a pong with the same timestamp.
fn on_internal_ping(ping: &InternalPing, ctx: &mut Context) {
	ctx.send(OutMessage::ConnectedPong { ping_send_time: ping.send_time }).unwrap();
}

/// Helper function to convert IPv6 addresses to equivalent IPv4 addresses if possible, or panic otherwise.
fn get_ipv4(ip: IpAddr) -> Ipv4Addr {
	match ip {
		IpAddr::V4(ip) => ip,
		IpAddr::V6(ip) => {
			if ip.is_loopback() {
				Ipv4Addr::LOCALHOST
			} else {
				panic!();
			}
		}
	}
}

/// Sends back a connection request accepted message with local address and remote address.
fn on_conn_req(conn_req: &ConnectionRequest, ctx: &mut Context) {
	if *conn_req.password != b"3.25 ND1"[..] {
		ctx.close_conn();
		return;
	};
	let peer_addr = ctx.peer_addr().unwrap();
	let peer_ip = get_ipv4(peer_addr.ip());
	let local_addr = ctx.local_addr().unwrap();
	let local_ip = get_ipv4(local_addr.ip());
	let message = OutMessage::ConnectionRequestAccepted {
		peer_ip,
		peer_port: peer_addr.port(),
		local_ip,
		local_port: local_addr.port()
	};
	ctx.send(message).unwrap();
}

/**
	Checks for network version and service ID, closing the connection if either doesn't match, otherwise sends back our own network version and service ID.
*/
fn on_handshake(inc_handshake: &IncHandshake, ctx: &mut Context) {
	const NETWORK_VERSION: u32 = 171022;

	if inc_handshake.network_version != NETWORK_VERSION {
		println!("wrong network version {}", inc_handshake.network_version);
		ctx.close_conn();
		return;
	}
	if inc_handshake.service_id != ServiceId::Client {
		println!("wrong service id {:?}", inc_handshake.service_id);
		ctx.close_conn();
		return;
	}
	let message = OutHandshake {
		network_version: NETWORK_VERSION,
		service_id: ServiceId::Auth,
	};
	ctx.send(message).unwrap();
}
