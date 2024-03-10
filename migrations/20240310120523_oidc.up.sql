CREATE TABLE oidc_codes (
	code TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	scope TEXT NOT NULL,
	response_type TEXT NOT NULL,
	client_id TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	state TEXT
) WITHOUT ROWID;

CREATE TABLE oidc_auth (
	auth TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL
) WITHOUT ROWID;
