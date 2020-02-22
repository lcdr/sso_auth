
# sso_auth

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
