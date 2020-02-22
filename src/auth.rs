//! The LU auth server.
use std::io::ErrorKind::{ConnectionReset, WouldBlock};
use std::io::Result as Res;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use endio::{Deserialize, LEWrite, Serialize};
use endio::LittleEndian as LE;

use crate::listeners::MsgCallback;
use crate::tcpudp::Connection;
use crate::TlsConfig;

/**
	The part of the server responsible for managing connections.

	This is split out from the rest of the server to avoid a cycle in the callback type.

	As for the name, the listeners get passed this, and it's not a single connection, so `Context` is the best I could come up with.
*/
pub struct Context<I, O> where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>> {
	/// All connections currently in use.
	conns: Vec<Connection<I, O>>,
	/**
		This index determines the active connection during iteration.

		The active connection will be used for sending responses in listeners.
	*/
	i: usize,
	/**
		Whether the active connection should be closed.

		Listeners can call `close_conn` multiple times, and a listener should still be able to send even when another has already closed the connection, so closing a connection is deferred until all listeners have been called.
	*/
	close_conn: bool,
}

impl<I, O> Context<I, O> where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>> {

	/// Sends a message using the active connection.
	pub fn send<IntoO: Into<O>>(&mut self, msg: IntoO) -> Res<()> {
		self.get_mut().send(msg)
	}

	/// Sends a message to all connections. The message is only serialized once.
	pub fn broadcast<IntoO: Into<O>>(&mut self, msg: IntoO) -> Res<()> {
		let mut data = vec![];
		data.write(&msg.into())?;
		for conn in self.conns.iter_mut() {
			conn.send_raw(&data[..])?;
		}
		Ok(())
	}

	/// Schedules the active connection to be closed at the next `advance` call.
	pub fn close_conn(&mut self) {
		self.close_conn = true;
	}

	/// Gets the remote address of the active connection.
	pub fn peer_addr(&self) -> Res<SocketAddr> {
		self.get().peer_addr()
	}

	/// Gets the local address of the active connection.
	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.get().local_addr()
	}

	/// Gets a reference to the active connection.
	fn get(&self) -> &Connection<I, O> {
		unsafe { self.conns.get_unchecked(self.i) }
	}

	/// Gets a mutable reference to the active connection.
	fn get_mut(&mut self) -> &mut Connection<I, O> {
		unsafe { self.conns.get_unchecked_mut(self.i) }
	}

	/// Adds a connection to the list of connections.
	fn push(&mut self, conn: Connection<I, O>) {
		self.conns.push(conn);
	}

	/// Calls `receive` on the active connection.
	fn receive(&mut self) -> Res<I> {
		self.get_mut().receive()
	}

	/// Resets iteration to start anew.
	fn reset(&mut self) {
		self.i = 0;
	}

	/// Returns whether iteration can proceed to the next connection.
	fn can_advance(&self) -> bool {
		self.i < self.conns.len()
	}

	/// Iterates, setting the next connection as the active connection. The current active connection is removed if it had been closed.
	fn advance(&mut self) {
		if self.close_conn {
			self.conns.swap_remove(self.i);
			self.close_conn = false;
		} else {
			self.i += 1;
		}
	}
}

/**
	A server.

	This is intentionally designed to be the absolute minimum of what a server has to be. It only keeps track of connections and checks for incoming messages, handing them over to a callback if there are any. Any additional functionality should be implemented in a message listener, not here.
*/
struct Server<I, O, C> where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>>,
		C: FnMut(&I, &mut Context<I, O>) {
	/// Listens to new incoming connections, not to be confused with message listeners.
	listener: TcpListener,
	/// Cert and key info for TLS.
	tls_config: TlsConfig,
	/// Keeps track of connections.
	ctx: Context<I, O>,
	/// Called on receiving a message.
	callback: C,
}

impl<I, O, C> Server<I, O, C> where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>>,
		C: FnMut(&I, &mut Context<I, O>) {

	/// Creates a new server with an address to listen on, a message callback, and a TLS config.
	fn new(addr: &str, tls_config: TlsConfig, callback: C) -> Res<Self> {
		let listener = TcpListener::bind(addr)?;
		listener.set_nonblocking(true)?;
		Ok(Server {
			listener,
			tls_config,
			ctx: Context {
				conns: vec![],
				i: 0,
				close_conn: false,
			},
			callback,
		})
	}

	/// Runs the server forever.
	fn run(&mut self) {
		loop {
			if let Err(x) = self.iteration() {
				dbg!(x);
			}
		}
	}

	/**
		Checks for incoming connections, checks existing connections for incoming messages and calls the callback if there are any.
	*/
	fn iteration(&mut self) -> Res<()> {
		while let Ok((stream, _addr)) = self.listener.accept() {
			#[cfg(feature="tls")]
			let stream = crate::tls::Transport::from(stream, &self.tls_config)?;
			#[cfg(not(feature="tls"))]
			let _ = self.tls_config;
			let conn = Connection::from(stream)?;
			self.ctx.push(conn);
		}
		self.ctx.reset();
		while self.ctx.can_advance() {
			loop {
				let res = self.ctx.receive();
				match res {
					Err(err) => {
						if err.kind() != WouldBlock {
							if err.kind() != ConnectionReset {
								dbg!(err);
							}
							self.ctx.close_conn();
						}
						break;
					}
					Ok(msg) => {
						(self.callback)(&msg, &mut self.ctx);
					}
				}
			}
			self.ctx.advance();
		}
		std::thread::sleep(Duration::from_millis(30));
		Ok(())
	}
}

/// Runs the LU auth server on 0.0.0.0:21836 using the provided database path and TLS config.
pub fn run(db_path: &str, tls_config: TlsConfig) {
	let listener = MsgCallback::new(db_path);
	let mut server = Server::new("0.0.0.0:21836", tls_config, |i, o| MsgCallback::on_msg(&listener, i, o)).unwrap();
	println!("Started up");
	server.run();
}
