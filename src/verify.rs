/*!
	The interface to world servers for verifying that a given session key is valid for a user.

	This is an HTTP(S) server on port 21835 listening for verification requests and returning responses.

	By default the server is HTTPS, if you choose to compile without TLS enabled, it will be HTTP.

	The server accepts requests to the URL `/verify/{username}/{session_key}`, where `session_key` is the key that should be checked for the user with the name `username`.

	The server returns a 200 OK response if the check was successful, returning `1` if the key matches and `0` if it doesn't.

	If the request was malformed, returns 400 Bad Request.

	If there was an error during the lookup, returns 500 Internal Server Error.
*/
use std::io::{Read, Result, Write};
use std::net::{TcpListener, TcpStream};

use diesel::prelude::*;
use diesel::dsl::{exists, select};

/// Run the verification server on 0.0.0.0:21835 using the provided database path and TLS config.
pub fn run(db_path: &str, config: crate::TlsConfig) {
	let conn = SqliteConnection::establish(db_path).unwrap();
	let listener = TcpListener::bind("0.0.0.0:21835").unwrap();

	for stream in listener.incoming() {
		let _ = handle(stream, &conn, &config);
	}
}

/// Handles a request and writes a response.
fn handle(stream: Result<TcpStream>, conn: &SqliteConnection, config: &crate::TlsConfig) -> Result<()> {
	#[cfg(feature="tls")]
	let mut stream = crate::tls::Transport::from(stream?, config)?;
	#[cfg(not(feature="tls"))]
	let _ = config;
	#[cfg(not(feature="tls"))]
	let mut stream = stream?;
	let mut buffer = [0; 512];
	stream.read(&mut buffer)?;
	stream.write(respond(&buffer, &conn))?;
	stream.flush()
}

/// Generates a response for the request.
fn respond<'a, 'b>(buffer: &'a [u8], conn: &'b SqliteConnection) -> &'a [u8] {
	let (username, sess_key) = match parse(&buffer) {
		Some(x) => x,
		None => { return b"HTTP/1.1 400 \r\n\r\n"; },
	};
	match verify(username, sess_key, &conn) {
		Some(true)  => b"HTTP/1.1 200 \r\n\r\n1",
		Some(false) => b"HTTP/1.1 200 \r\n\r\n0",
		None        => b"HTTP/1.1 500 \r\n\r\n",
	}
}

macro_rules! is {
	($x:expr, $y:expr) => {
		if $x? != $y { return None; }
	}
}

/// Parses an HTTP request and returns the provided values for username and session key, or None if there was a parsing error.
fn parse(buffer: &[u8]) -> Option<(&str, &str)> {
	let first_line = buffer.split(|x| *x == '\n' as u8).next()?;
	let mut parts = first_line.split(|x| *x == ' ' as u8);
	is!(parts.next(), b"GET");
	let path = parts.next()?;
	is!(parts.next(), b"HTTP/1.1\r");
	let mut path_parts = path[1..].split(|x| *x == '/' as u8);
	is!(path_parts.next(), b"verify");
	let provided_username = path_parts.next()?;
	let provided_sess_key = path_parts.next()?;
	let username = std::str::from_utf8(provided_username).ok()?;
	let sess_key = std::str::from_utf8(provided_sess_key).ok()?;
	Some((username, sess_key))
}

/**
	Looks up the given combination of username and session key in the database.

	Returns whether the combination exists in the DB, or None if any error occurred.
*/
fn verify(provided_username: &str, provided_sess_key: &str, conn: &SqliteConnection) -> Option<bool> {
	use crate::schema::users::dsl::{users, username, session_key};

	select(exists(users
	.filter(username   .eq(provided_username))
	.filter(session_key.eq(provided_sess_key))))
	.get_result(conn).ok()
}
