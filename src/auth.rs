//! The LU auth server.
use base_server::server::Server;

use crate::listeners::MsgCallback;
use base_server::TlsConfig;

/// Runs the LU auth server on 0.0.0.0:21836 using the provided database path and TLS config.
pub fn run(db_path: &str, tls_config: TlsConfig) {
	let listener = MsgCallback::new(db_path);
	let mut server = Server::new("0.0.0.0:21836", tls_config, |i, o| MsgCallback::on_msg(&listener, i, o)).unwrap();
	println!("Started up");
	server.run();
}
