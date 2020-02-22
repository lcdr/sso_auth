//! Alternative drop-in TCP replacement with TLS encryption.
use std::io::{Read, Write};
use std::io::Result as Res;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::Session;

pub struct Transport {
	stream: rustls::StreamOwned<rustls::ServerSession, TcpStream>,
}

impl Transport {
	pub fn from(sock: TcpStream, config: &Arc<rustls::ServerConfig>) -> Res<Self> {
		let sess = rustls::ServerSession::new(config);
		sock.set_nonblocking(true)?;
		let mut stream = rustls::StreamOwned::new(sess, sock);

		while stream.sess.is_handshaking() {
			while let Err(e) = stream.sess.complete_io(&mut stream.sock) {
				if e.kind() != std::io::ErrorKind::WouldBlock {
					return Err(e);
				}
				std::thread::sleep(std::time::Duration::from_millis(30));
			}
		}

		Ok(Transport { stream } )
	}

	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.stream.sock.local_addr()
	}

	pub fn peer_addr(&self) -> Res<SocketAddr> {
		self.stream.sock.peer_addr()
	}

	pub fn set_nonblocking(&self, nonblocking: bool) -> Res<()> {
		self.stream.sock.set_nonblocking(nonblocking)
	}
}

impl Read for Transport {
	fn read(&mut self, buf: &mut [u8]) -> Res<usize> {
		self.stream.read(buf)
	}
}

impl Write for Transport {
	fn write(&mut self, buf: &[u8]) -> Res<usize> {
		self.stream.write(buf)
	}

	fn flush(&mut self) -> Res<()> {
		self.stream.flush()
	}
}
