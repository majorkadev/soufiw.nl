# neverlose-server

Dynamic, DB-backed server that builds per-user `module.bin` on the fly using nl_parser. Serves modules over WebSocket and provides HTTP admin/API endpoints.

## Prerequisites

- Rust toolchain (stable)
- `flatc` (FlatBuffers compiler) — available via `nix-shell -p flatbuffers`
- PostgreSQL 16+
- `pkg-config` and `openssl` dev headers

## Setup

### 1. Start PostgreSQL

```bash
docker run -d --name neverlose-pg \
  -e POSTGRES_USER=neverlose \
  -e POSTGRES_PASSWORD=neverlose \
  -e POSTGRES_DB=neverlose \
  -p 5432:5432 \
  postgres:16
```

### 2. Build

```bash
nix-shell -p cargo rustc flatbuffers pkg-config openssl --run "cargo build"
```

### 3. Run

```bash
DATABASE_URL=postgres://neverlose:neverlose@localhost/neverlose cargo run
```

Migrations run automatically on startup.

## Quick start

### Seed the database

Parses the embedded `module.bin` template into the database **and** creates a default user from it (username, auth_token, log entries all come from the original module). The default serial is also populated.

```bash
curl -X POST http://localhost:30031/admin/seed
```

Returns `base_module_id`, `user_id`, `username`, and `auth_token`. You can immediately use the `auth_token` to connect via WebSocket.

### Connect via WebSocket

```bash
wscat -c "ws://localhost:30030/?token=<auth_token>"
```

Send any message first, then receive 3 frames:
1. Auth JSON (`{"Type":"Auth","Message":"...","Data":"..."}`)
2. Per-user `module.bin` (built dynamically from DB)
3. `key.bin` (static, shared)

## Admin API

### Create additional users

```bash
curl -X POST http://localhost:30031/admin/users \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "someone",
    "auth_token": "unique_token_here",
    "base_module_id": "<id from seed>",
    "serial": "<base64 serial string>"
  }'
```

### List users

```bash
curl http://localhost:30031/admin/users
```

### Log entries (CRUD)

```bash
# List
curl http://localhost:30031/admin/users/<user_id>/logs

# Create
curl -X POST http://localhost:30031/admin/users/<user_id>/logs \
  -H 'Content-Type: application/json' \
  -d '{"entry_id": 1, "timestamp": 1234567890, "entry_type": "Script", "author": "test"}'

# Update
curl -X PUT http://localhost:30031/admin/users/<user_id>/logs/<log_id> \
  -H 'Content-Type: application/json' \
  -d '{"entry_id": 1, "timestamp": 1234567890, "entry_type": "Config", "author": "updated"}'

# Delete
curl -X DELETE http://localhost:30031/admin/users/<user_id>/logs/<log_id>
```

## Ports

| Port  | Protocol  | Purpose              |
|-------|-----------|----------------------|
| 30031 | HTTP      | API + admin endpoints|
| 30030 | WebSocket | Module delivery      |

## Logging

All HTTP and WebSocket requests are logged to the console. Unknown POST bodies and WebSocket binary messages are automatically decrypted (AES-128-CBC) and decompressed (LZ4) where possible, with the plaintext logged for inspection.
