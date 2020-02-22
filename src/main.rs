/*!
	## A Single-Sign-On (SSO) authentication server for LU.

	This server is meant to be able to support players from multiple server projects simultaneously, as well as supporting players changing the server project they play on. This has multiple advantages over each project hosting their own auth server:

	- Passwords are only sent to the SSO auth. This means that players can choose to play on server instances where they don't fully trust the host with their password.

	- Similarly, the client sends some info about hardware and OS configuration to the auth server. Some players might not want this sensitive information to be available to server projects.

	- Players don't need to create accounts to play on a new server project, as long as they already have an account set up with the SSO auth. Server projects can configure their servers to automatically create the DB entries for new players once they've been verified by the SSO auth.

	- Players don't need to do any boot.cfg editing to switch server projects. Instead they can change the project via a web interface.

	### Implementation

	This server actually consists of two servers:

	- The conventional LU auth server using LU's protocol (over TCP/UDP), which handles the login and sends back the session key and redirect address.

	- An HTTP(S) verification server, which is used as an API for world servers to check whether a client-supplied username and session key are valid.

	The user database is changed to add fields for the world server address to redirect to. Users are meant to be able to change this themselves, making it possible to change server projects.

	If you are a server project maintainer and are looking to integrate with the SSO auth, see the documentation for the verification server for details on the API.

	### Compilation

	Compilation requires a stable rust toolchain. To build, `cargo build --release` should work without problems.

	By default, both the auth server and the verification server use TLS encryption. If you want to disable encryption (typically for hosting a server on LAN), use `cargo build --release --no-default-features`.

	### Database setup

	The server requires an sqlite database. You can use diesel to setup the DB with the appropriate schema:

	`cargo install diesel_cli --no-default-features --features sqlite`

	`diesel migration run`

	### TLS setup

	If you did not disable TLS during compilation, you will need a certificate file and key file to run the server. Detailed instructions on how to generate these are out of scope for this readme, but there are guides on how to do this with letsencrypt online.

	### Server setup

	The server expects a TOML configuration file named `config.toml` next to the executable, in the format:

	```toml
	[db]
	path="<path to sqlite file>"
	[tls]
	cert_path="<path to cert file>"
	key_path="<path to key file>"
	```

	Additionally, make sure to whitelist TCP ports 21835 and 21836 in your firewall.

	With this setup, the server should be runnable without problems.
*/
#[macro_use]
extern crate diesel;

mod auth;
mod listeners;
mod models;
mod schema;
mod tcpudp;
mod verify;
#[cfg(feature="tls")] mod tls;

#[cfg(feature="tls")] use std::sync::Arc;
use std::thread;

#[cfg(feature="tls")]      type TlsConfig = Arc<rustls::ServerConfig>;
#[cfg(not(feature="tls"))] type TlsConfig = ();

use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
	db: DbConf,
	tls: TlsConf,
}

#[derive(Deserialize)]
struct DbConf {
	path: String,
}

#[derive(Deserialize)]
struct TlsConf {
	#[cfg(feature="tls")]
	cert_path: String,
	#[cfg(feature="tls")]
	key_path: String,
}

#[cfg(feature="tls")]
fn create_config(conf: TlsConf) -> TlsConfig {
	let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());

	let certfile = std::fs::File::open(conf.cert_path).expect("cannot open certificate file");
	let mut reader = std::io::BufReader::new(certfile);
	let certs = rustls::internal::pemfile::certs(&mut reader).unwrap();

	let keyfile = std::fs::File::open(conf.key_path).expect("cannot open key file");
	let mut reader = std::io::BufReader::new(keyfile);
	let keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader).expect("file contains invalid pkcs8 private key (encrypted keys not supported)");

	config.set_single_cert(certs, keys[0].clone()).unwrap();
	Arc::new(config)
}

#[cfg(not(feature="tls"))]
fn create_config(_conf: TlsConf) -> TlsConfig {
	()
}

static mut DB_PATH : String = String::new();

/// Runs both the auth and the verification server.
fn main() {
	let mut exe_path = std::env::current_exe().expect("program location unknown");
	exe_path.pop();
	exe_path.push("config.toml");
	let config = std::fs::read_to_string(exe_path).expect("cannot open config file config.toml");
	let config: Config = toml::from_str(&config).expect("config file parsing error");

	let config1 = create_config(config.tls);
	let config2 = config1.clone();

	unsafe { DB_PATH = config.db.path; }

	thread::spawn(move || { verify::run(unsafe { &DB_PATH }, config1) });
	auth::run(unsafe { &DB_PATH }, config2);
}
