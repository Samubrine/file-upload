-- CipherVault Initial SQLite Schema v1.0
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS payloads (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('profile', 'file_metadata', 'file_content')),
    context_owner_id TEXT NOT NULL,
    context_file_id TEXT,
    content_revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_variants (
    payload_id TEXT NOT NULL REFERENCES payloads(id) ON DELETE CASCADE,
    variant_id TEXT NOT NULL,
    envelope BLOB NOT NULL,
    envelope_bytes INTEGER NOT NULL,
    PRIMARY KEY(payload_id, variant_id)
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username_lookup BLOB UNIQUE NOT NULL,
    email_lookup BLOB UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    profile_payload_id TEXT UNIQUE NOT NULL REFERENCES payloads(id),
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token_hash BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_payload_id TEXT UNIQUE NOT NULL REFERENCES payloads(id),
    metadata_payload_id TEXT UNIQUE NOT NULL REFERENCES payloads(id),
    content_revision INTEGER NOT NULL DEFAULT 1,
    revision INTEGER NOT NULL DEFAULT 1,
    listed INTEGER NOT NULL DEFAULT 0 CHECK(listed IN (0, 1)),
    logical_bytes INTEGER NOT NULL,
    physical_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    view_metadata INTEGER NOT NULL DEFAULT 0 CHECK(view_metadata IN (0, 1)),
    download INTEGER NOT NULL DEFAULT 0 CHECK(download IN (0, 1)),
    created_at TEXT NOT NULL,
    PRIMARY KEY(file_id, recipient_id),
    CHECK(view_metadata = 1 OR download = 1),
    CHECK(download = 0 OR view_metadata = 1)
);

CREATE TABLE IF NOT EXISTS quota_reservations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    logical_bytes INTEGER NOT NULL,
    predicted_physical_bytes INTEGER NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_listed ON files(listed);
CREATE INDEX IF NOT EXISTS idx_grants_recipient_id ON grants(recipient_id);
CREATE INDEX IF NOT EXISTS idx_quota_user_id ON quota_reservations(user_id);

