create table users (
  id integer not null primary key,
  username text unique not null,
	password text not null,
	redirect_host text not null,
	redirect_port integer not null,
	session_key text not null
)
