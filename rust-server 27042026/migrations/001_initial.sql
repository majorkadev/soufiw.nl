CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE base_modules (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                TEXT NOT NULL UNIQUE,
    version             INTEGER NOT NULL DEFAULT 0,
    author              TEXT NOT NULL DEFAULT '',
    checksum            BIGINT NOT NULL DEFAULT 0,
    buffer_capacity     BIGINT NOT NULL DEFAULT 0,
    enabled             INTEGER NOT NULL DEFAULT 1,
    skin_data_msgpack   BYTEA NOT NULL,
    languages_json      JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        TEXT NOT NULL UNIQUE,
    auth_token      TEXT NOT NULL UNIQUE,
    base_module_id  UUID NOT NULL REFERENCES base_modules(id),
    avatar_png      BYTEA,
    serial          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE log_entries (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry_id    INTEGER NOT NULL,
    timestamp   INTEGER NOT NULL,
    entry_type  TEXT NOT NULL CHECK (entry_type IN ('Script', 'Config')),
    author      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_log_entries_user_type ON log_entries(user_id, entry_type);
CREATE INDEX idx_users_auth_token ON users(auth_token);
