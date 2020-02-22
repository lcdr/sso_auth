/*!
	The TCP- and UDP-based Raknet replacement protocol.

	The protocol is designed to make full use of the mechanisms of the underlying protocols and be as simple as possible itself.

	Reliable packets are sent over TCP, which provides all necessary mechanisms for reliability and ordering. The only additional mechanism needed is message framing, as TCP is a stream-oriented protocol and doesn't have a concept of distinct messages. To implement this, each message is prefixed with a 32-bit length field (in bytes).

	Unreliable packets are sent over UDP, prefixed with an 8-bit ID for distinguishing between `Unreliable` (ID 0) and `UnreliableSequenced` (ID 1). In the case of `UnreliableSequenced`, a 32-bit sequence number is prefixed as well. To keep the protocol simple, no support for packet splitting is included, unreliable packets must be shorter than the MTU.
*/
use std::io::Error;
use std::io::ErrorKind::WouldBlock;
use std::io::Result as Res;
use std::marker::PhantomData;

use std::net::SocketAddr;
#[cfg(test)]
use std::net::ToSocketAddrs;

use endio::{Deserialize, LEWrite, Serialize};
use endio::LittleEndian as LE;

#[cfg(feature="tls")]      use crate::tls::Transport as ReliableTransport;
#[cfg(not(feature="tls"))] use std::net::TcpStream as ReliableTransport;

/// Buffer for keeping packets that were only read in part.
struct BufferOffset {
	reading_length: bool,
	offset: usize,
	length: [u8; 4],
	buffer: Box<[u8]>,
}

/**
	Supports sending and receiving messages in the TCP/UDP protocol.

	By substituting the I and O parameters with types representing the messages you intend to receive (I) and send (O), you can construct an API that only allows sending and receiving of correctly formatted messages, with (de-)serialization done automatically.

	Note: UDP support is not present in this variant as the auth server doesn't need it.
*/
pub struct Connection<I, O> {
	tcp: ReliableTransport,
	packet: BufferOffset,
	in_type: PhantomData<I>,
	out_type: PhantomData<O>,
}

impl<I, O> Connection<I, O> where
		for<'a> I: Deserialize<LE, &'a [u8]>,
		for<'b> &'b O: Serialize<LE, Vec<u8>> {
	/// Constructs a connection from a previously established TCP or TLS connection.
	pub fn from(tcp: ReliableTransport) -> Res<Self> {
		tcp.set_nonblocking(true)?;
		Ok(Self {
			tcp,
			packet: BufferOffset { reading_length: true, offset: 0, length: [0; 4], buffer: Box::new([]) },
			in_type: PhantomData,
			out_type: PhantomData,
		})
	}

	#[cfg(test)]
	fn connect<A: ToSocketAddrs>(addr: A) -> Res<Self> {
		let tcp = ReliableTransport::connect(&addr)?;
		tcp.set_nonblocking(true)?;
		Ok(Self {
			tcp,
			packet: BufferOffset { reading_length: true, offset: 0, length: [0; 4], buffer: Box::new([]) },
			in_type: PhantomData,
			out_type: PhantomData,
		})
	}

	/// Gets the remote address this is connected to.
	pub fn peer_addr(&self) -> Res<SocketAddr> {
		self.tcp.peer_addr()
	}

	/// Gets the local address this is listening on.
	pub fn local_addr(&self) -> Res<SocketAddr> {
		self.tcp.local_addr()
	}

	/// Sends a message over TCP.
	pub fn send<IntoO: Into<O>>(&mut self, msg: IntoO) -> Res<()> {
		let mut data = vec![];
		data.write(&msg.into())?;
		self.send_raw(&data[..])
	}

	/// Sends bytes over TCP.
	pub fn send_raw(&mut self, data: &[u8]) -> Res<()> {
		self.tcp.write(data.len() as u32)?;
		std::io::Write::write(&mut self.tcp, &data)?;
		Ok(())
	}

	/// Receives a message over TCP.
	pub fn receive(&mut self) -> Res<I> {
		use endio::LERead;
		let x = &mut &*self.receive_raw()?;
		x.read()
	}

	/// Receives bytes over TCP.
	fn receive_raw(&mut self) -> Res<Box<[u8]>> {
		use std::io::Read;

		if self.packet.reading_length {
			while self.packet.offset < self.packet.length.len() {
				let n = self.tcp.read(&mut self.packet.length[self.packet.offset..])?;
				if n == 0 {
					return Err(Error::new(WouldBlock, ""));
				}
				self.packet.offset += n;
			}
			self.packet.reading_length = false;
			self.packet.offset = 0;
			self.packet.buffer = vec![0; u32::from_le_bytes(self.packet.length) as usize].into_boxed_slice();
		}
		while self.packet.offset < self.packet.buffer.len() {
			let n = self.tcp.read(&mut self.packet.buffer[self.packet.offset..])?;
			if n == 0 {
				return Err(Error::new(WouldBlock, ""));
			}
			self.packet.offset += n;
		}
		self.packet.reading_length = true;
		self.packet.offset = 0;
		let mut b = Box::from(&[][..]);
		std::mem::swap(&mut self.packet.buffer, &mut b);
		Ok(b)
	}
}

#[cfg(test)]
mod tests_tcp {
	use std::io::ErrorKind::{ConnectionAborted, WouldBlock};
	use std::net::{Shutdown, TcpListener, TcpStream};
	use endio::LERead;
	use endio::LEWrite;
	use lu_packets::auth_server::Message as IncMessage;
	use lu_packets::auth_client::Message as OutMessage;
	use super::Connection as C;

	type Connection = C<IncMessage, OutMessage>;

	fn setup() -> (Connection, TcpStream) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let client = Connection::connect(listener.local_addr().unwrap()).unwrap();
		let server = listener.accept().unwrap().0;
		(client, server)
	}

	fn loop_wait(conn: &mut Connection) -> Box<[u8]> {
		loop {
			let res = conn.receive_raw();
			match res {
				Ok(x) => break x,
				Err(e) => {
					if e.kind() != WouldBlock {
						panic!();
					}
				}
			}
		}
	}

	#[test]
	fn recv_whole() {
		let (mut client, mut server) = setup();
		server.write(4u32).unwrap();
		server.write(1u16).unwrap();
		server.write(2u16).unwrap();
		let packet = loop_wait(&mut client);
		assert_eq!(&*packet, b"\x01\x00\x02\x00");
	}

	#[test]
	fn recv_partial_len_before() {
		let (mut client, mut server) = setup();
		server.write(1u16).unwrap();
		let res = client.receive_raw();
		assert!(res.is_err());
		server.write(0u16).unwrap();
		let res = client.receive_raw();
		assert!(res.is_err());
		server.write(0u8).unwrap();
		let packet = loop_wait(&mut client);
		assert_eq!(packet.len(), 1);
	}

	#[test]
	fn recv_partial_len_after() {
		let (mut client, mut server) = setup();
		server.write(1u32).unwrap();
		server.write(0u8).unwrap();
		server.write(1u16).unwrap();
		let _packet = loop_wait(&mut client);
		server.write(0u16).unwrap();
		let res = client.receive_raw();
		assert!(res.is_err());
		server.write(0u8).unwrap();
		let packet = loop_wait(&mut client);
		assert_eq!(packet.len(), 1);
	}

	#[test]
	fn recv_partial_data() {
		let (mut client, mut server) = setup();
		server.write(4u32).unwrap();
		server.write(1u16).unwrap();
		let res = client.receive_raw();
		assert!(res.is_err());
		server.write(2u16).unwrap();
		let packet = loop_wait(&mut client);
		assert_eq!(&*packet, b"\x01\x00\x02\x00");
	}

	#[test]
	fn send_ok() {
		let (mut client, mut server) = setup();
		client.send_raw(&[42]).unwrap();
		assert_eq!(server.read::<u32>().unwrap(), 1);
		assert_eq!(server.read::<u8>().unwrap(), 42);
	}

	#[test]
	fn send_shutdown() {
		let (mut client, server) = setup();
		server.shutdown(Shutdown::Both).unwrap();
		assert_eq!(client.send_raw(&[42]).unwrap_err().kind(), ConnectionAborted);
	}
}
