CREATE TABLE tokens (
	code TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	user TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	bound_to TEXT,
	metadata TEXT NOT NULL,

	-- If a parent token that bound_to points to is deleted, delete this token as well
	CONSTRAINT fk_bound_to
		FOREIGN KEY(bound_to)
		REFERENCES tokens(code)
		ON DELETE CASCADE
) WITHOUT ROWID;
