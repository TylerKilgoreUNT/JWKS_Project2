# JWKS_Project2

This is the repository for Project 2: Extending the JWKS server for CSCE 3550: Spring 2026.

## Overview

This project implements a JWKS server backed by SQLite for persistent RSA private key storage.

- Database file: `totally_not_my_privateKeys.db`
- Table schema:

```sql
CREATE TABLE IF NOT EXISTS keys(
	kid INTEGER PRIMARY KEY AUTOINCREMENT,
	key BLOB NOT NULL,
	exp INTEGER NOT NULL
)
```

On startup, the server creates/opens the database and ensures at least:

- one expired key (`exp <= now`)
- one valid key (`exp > now`)

## Endpoints

### `POST /auth`

- Reads a private key from SQLite using parameterized queries.
- If `?expired` is present, signs with an expired key.
- Otherwise signs with a valid key.
- Returns a JWT signed with RS256.

### `GET /.well-known/jwks.json`

- Reads all valid (non-expired) private keys from SQLite.
- Converts each to a public JWK.
- Returns a JWKS response containing only valid keys.

## Security Notes

- All SQL interactions use query parameters (`?1`, `?2`) to avoid SQL injection.
- Private keys are stored as PKCS#1 PEM bytes in the `BLOB` column and deserialized when needed.

## Running

```bash
cargo run
```

Server listens on `127.0.0.1:8080`.

## Testing

```bash
cargo test
```

The test suite covers:

- database initialization and key seeding
- JWT issuance for valid and expired key paths
- JWKS output containing only valid keys
- method handling on endpoints
