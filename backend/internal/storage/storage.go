package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("record not found")
	ErrConflict      = errors.New("conflict: constraint violation or optimistic lock mismatch")
	ErrQuotaExceeded = errors.New("quota exceeded")
)

type DB struct {
	*sql.DB
}

type UserRow struct {
	ID               string
	UsernameLookup   []byte
	EmailLookup      []byte
	PasswordHash     string
	ProfilePayloadID string
	Revision         int64
	CreatedAt        string
}

type SessionRow struct {
	TokenHash     []byte
	UserID        string
	CSRFTokenHash []byte
	CreatedAt     string
	ExpiresAt     string
}

type PayloadRow struct {
	ID              string
	Kind            string // profile, file_metadata, file_content
	ContextOwnerID  string
	ContextFileID   *string
	ContentRevision int64
	CreatedAt       string
}

type PayloadVariantRow struct {
	PayloadID     string
	VariantID     string
	Envelope      []byte
	EnvelopeBytes int64
}

type FileRow struct {
	ID                string
	OwnerID           string
	ContentPayloadID  string
	MetadataPayloadID string
	ContentRevision   int64
	Revision          int64
	Listed            bool
	LogicalBytes      int64
	PhysicalBytes     int64
	CreatedAt         string
	UpdatedAt         string
}

type GrantRow struct {
	FileID       string
	RecipientID  string
	ViewMetadata bool
	Download     bool
	CreatedAt    string
}

type QuotaUsage struct {
	LogicalUsedBytes  int64
	PhysicalUsedBytes int64
	FileCount         int64
}

// OpenDB opens a SQLite database connection with proper WAL and foreign key settings,
// and applies database migrations.
func OpenDB(dataSourceName string) (*DB, error) {
	if dir := filepath.Dir(dataSourceName); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Busy timeout 5s, foreign keys ON, WAL mode
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to exec pragma %s: %w", p, err)
		}
	}

	db.SetMaxOpenConns(1) // Single writer model for SQLite reliability

	sdb := &DB{DB: db}
	if err := sdb.applyInitialSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}

	return sdb, nil
}

func (db *DB) applyInitialSchema() error {
	schema := `
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
`
	_, err := db.Exec(schema)
	return err
}

func (db *DB) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// User methods
func (db *DB) CreateUser(tx *sql.Tx, u UserRow) error {
	query := `
INSERT INTO users (id, username_lookup, email_lookup, password_hash, profile_payload_id, revision, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);
`
	_, err := tx.Exec(query, u.ID, u.UsernameLookup, u.EmailLookup, u.PasswordHash, u.ProfilePayloadID, u.Revision, u.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (db *DB) GetUserByID(tx *sql.Tx, id string) (*UserRow, error) {
	query := `
SELECT id, username_lookup, email_lookup, password_hash, profile_payload_id, revision, created_at
FROM users WHERE id = ?;
`
	var u UserRow
	err := tx.QueryRow(query, id).Scan(&u.ID, &u.UsernameLookup, &u.EmailLookup, &u.PasswordHash, &u.ProfilePayloadID, &u.Revision, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (db *DB) GetUserByUsernameLookup(tx *sql.Tx, lookup []byte) (*UserRow, error) {
	query := `
SELECT id, username_lookup, email_lookup, password_hash, profile_payload_id, revision, created_at
FROM users WHERE username_lookup = ?;
`
	var u UserRow
	err := tx.QueryRow(query, lookup).Scan(&u.ID, &u.UsernameLookup, &u.EmailLookup, &u.PasswordHash, &u.ProfilePayloadID, &u.Revision, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (db *DB) GetUserByEmailLookup(tx *sql.Tx, lookup []byte) (*UserRow, error) {
	query := `
SELECT id, username_lookup, email_lookup, password_hash, profile_payload_id, revision, created_at
FROM users WHERE email_lookup = ?;
`
	var u UserRow
	err := tx.QueryRow(query, lookup).Scan(&u.ID, &u.UsernameLookup, &u.EmailLookup, &u.PasswordHash, &u.ProfilePayloadID, &u.Revision, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (db *DB) UpdateUserProfile(tx *sql.Tx, id string, emailLookup []byte, newProfilePayloadID string, expectedRev, newRev int64) error {
	query := `
UPDATE users
SET email_lookup = ?, profile_payload_id = ?, revision = ?
WHERE id = ? AND revision = ?;
`
	res, err := tx.Exec(query, emailLookup, newProfilePayloadID, newRev, id, expectedRev)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrConflict
		}
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict // Optimistic concurrency check failed
	}
	return nil
}

func (db *DB) UpdateUserPassword(tx *sql.Tx, id, passwordHash string, expectedRev, newRev int64) error {
	query := `
UPDATE users
SET password_hash = ?, revision = ?
WHERE id = ? AND revision = ?;
`
	res, err := tx.Exec(query, passwordHash, newRev, id, expectedRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (db *DB) DeleteUser(tx *sql.Tx, id string) error {
	// Must explicitly delete profile payload and user's owned files' payloads
	// First fetch user to get profile payload id
	u, err := db.GetUserByID(tx, id)
	if err != nil {
		return err
	}

	// Fetch all owned files to get content and metadata payload IDs
	rows, err := tx.Query("SELECT content_payload_id, metadata_payload_id FROM files WHERE owner_id = ?", id)
	if err != nil {
		return err
	}
	var payloadIDs []string
	for rows.Next() {
		var cID, mID string
		if err := rows.Scan(&cID, &mID); err != nil {
			rows.Close()
			return err
		}
		payloadIDs = append(payloadIDs, cID, mID)
	}
	rows.Close()

	// Delete user (cascades to files, grants, sessions)
	if _, err := tx.Exec("DELETE FROM users WHERE id = ?", id); err != nil {
		return err
	}

	// Explicitly delete user's profile payload
	if _, err := tx.Exec("DELETE FROM payloads WHERE id = ?", u.ProfilePayloadID); err != nil {
		return err
	}

	// Explicitly delete all file payloads
	for _, pid := range payloadIDs {
		if _, err := tx.Exec("DELETE FROM payloads WHERE id = ?", pid); err != nil {
			return err
		}
	}

	return nil
}

// Session methods
func (db *DB) CreateSession(tx *sql.Tx, s SessionRow) error {
	query := `
INSERT INTO sessions (token_hash, user_id, csrf_token_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);
`
	_, err := tx.Exec(query, s.TokenHash, s.UserID, s.CSRFTokenHash, s.CreatedAt, s.ExpiresAt)
	return err
}

func (db *DB) GetSession(tx *sql.Tx, tokenHash []byte) (*SessionRow, error) {
	query := `
SELECT token_hash, user_id, csrf_token_hash, created_at, expires_at
FROM sessions WHERE token_hash = ?;
`
	var s SessionRow
	err := tx.QueryRow(query, tokenHash).Scan(&s.TokenHash, &s.UserID, &s.CSRFTokenHash, &s.CreatedAt, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &s, err
}

func (db *DB) DeleteSession(tx *sql.Tx, tokenHash []byte) error {
	_, err := tx.Exec("DELETE FROM sessions WHERE token_hash = ?", tokenHash)
	return err
}

func (db *DB) DeleteOtherSessions(tx *sql.Tx, userID string, currentTokenHash []byte) error {
	_, err := tx.Exec("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", userID, currentTokenHash)
	return err
}

func (db *DB) PurgeExpiredSessions(tx *sql.Tx) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.Exec("DELETE FROM sessions WHERE expires_at < ?", now)
	return err
}

// Payload and PayloadVariants methods
func (db *DB) CreatePayloadWithVariants(tx *sql.Tx, p PayloadRow, variants []PayloadVariantRow) error {
	if len(variants) != 14 {
		return fmt.Errorf("must provide exactly 14 payload variants, got %d", len(variants))
	}
	pQuery := `
INSERT INTO payloads (id, kind, context_owner_id, context_file_id, content_revision, created_at)
VALUES (?, ?, ?, ?, ?, ?);
`
	if _, err := tx.Exec(pQuery, p.ID, p.Kind, p.ContextOwnerID, p.ContextFileID, p.ContentRevision, p.CreatedAt); err != nil {
		return err
	}

	vQuery := `
INSERT INTO payload_variants (payload_id, variant_id, envelope, envelope_bytes)
VALUES (?, ?, ?, ?);
`
	stmt, err := tx.Prepare(vQuery)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, v := range variants {
		if _, err := stmt.Exec(v.PayloadID, v.VariantID, v.Envelope, v.EnvelopeBytes); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetPayload(tx *sql.Tx, id string) (*PayloadRow, error) {
	query := `
SELECT id, kind, context_owner_id, context_file_id, content_revision, created_at
FROM payloads WHERE id = ?;
`
	var p PayloadRow
	err := tx.QueryRow(query, id).Scan(&p.ID, &p.Kind, &p.ContextOwnerID, &p.ContextFileID, &p.ContentRevision, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func (db *DB) GetPayloadVariant(tx *sql.Tx, payloadID, variantID string) (*PayloadVariantRow, error) {
	query := `
SELECT payload_id, variant_id, envelope, envelope_bytes
FROM payload_variants WHERE payload_id = ? AND variant_id = ?;
`
	var v PayloadVariantRow
	err := tx.QueryRow(query, payloadID, variantID).Scan(&v.PayloadID, &v.VariantID, &v.Envelope, &v.EnvelopeBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

func (db *DB) DeletePayload(tx *sql.Tx, id string) error {
	// Cascades to payload_variants
	_, err := tx.Exec("DELETE FROM payloads WHERE id = ?", id)
	return err
}

// File methods
func (db *DB) CreateFile(tx *sql.Tx, f FileRow) error {
	query := `
INSERT INTO files (id, owner_id, content_payload_id, metadata_payload_id, content_revision, revision, listed, logical_bytes, physical_bytes, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`
	listedInt := 0
	if f.Listed {
		listedInt = 1
	}
	_, err := tx.Exec(query, f.ID, f.OwnerID, f.ContentPayloadID, f.MetadataPayloadID, f.ContentRevision, f.Revision, listedInt, f.LogicalBytes, f.PhysicalBytes, f.CreatedAt, f.UpdatedAt)
	return err
}

func (db *DB) GetFileByID(tx *sql.Tx, id string) (*FileRow, error) {
	query := `
SELECT id, owner_id, content_payload_id, metadata_payload_id, content_revision, revision, listed, logical_bytes, physical_bytes, created_at, updated_at
FROM files WHERE id = ?;
`
	var f FileRow
	var listedInt int
	err := tx.QueryRow(query, id).Scan(&f.ID, &f.OwnerID, &f.ContentPayloadID, &f.MetadataPayloadID, &f.ContentRevision, &f.Revision, &listedInt, &f.LogicalBytes, &f.PhysicalBytes, &f.CreatedAt, &f.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	f.Listed = (listedInt == 1)
	return &f, err
}

func (db *DB) ListFilesMine(tx *sql.Tx, ownerID string, offset, limit int) ([]FileRow, int, error) {
	var total int
	if err := tx.QueryRow("SELECT COUNT(*) FROM files WHERE owner_id = ?", ownerID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
SELECT id, owner_id, content_payload_id, metadata_payload_id, content_revision, revision, listed, logical_bytes, physical_bytes, created_at, updated_at
FROM files
WHERE owner_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;
`
	rows, err := tx.Query(query, ownerID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []FileRow
	for rows.Next() {
		var f FileRow
		var listedInt int
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.ContentPayloadID, &f.MetadataPayloadID, &f.ContentRevision, &f.Revision, &listedInt, &f.LogicalBytes, &f.PhysicalBytes, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, err
		}
		f.Listed = (listedInt == 1)
		list = append(list, f)
	}
	return list, total, nil
}

func (db *DB) ListFilesShared(tx *sql.Tx, recipientID string, offset, limit int) ([]FileRow, int, error) {
	countQuery := `
SELECT COUNT(*)
FROM files f
INNER JOIN grants g ON f.id = g.file_id
WHERE g.recipient_id = ? AND (g.view_metadata = 1 OR g.download = 1);
`
	var total int
	if err := tx.QueryRow(countQuery, recipientID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
SELECT f.id, f.owner_id, f.content_payload_id, f.metadata_payload_id, f.content_revision, f.revision, f.listed, f.logical_bytes, f.physical_bytes, f.created_at, f.updated_at
FROM files f
INNER JOIN grants g ON f.id = g.file_id
WHERE g.recipient_id = ? AND (g.view_metadata = 1 OR g.download = 1)
ORDER BY f.created_at DESC
LIMIT ? OFFSET ?;
`
	rows, err := tx.Query(query, recipientID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []FileRow
	for rows.Next() {
		var f FileRow
		var listedInt int
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.ContentPayloadID, &f.MetadataPayloadID, &f.ContentRevision, &f.Revision, &listedInt, &f.LogicalBytes, &f.PhysicalBytes, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, err
		}
		f.Listed = (listedInt == 1)
		list = append(list, f)
	}
	return list, total, nil
}

func (db *DB) ListFilesListed(tx *sql.Tx, offset, limit int) ([]FileRow, int, error) {
	var total int
	if err := tx.QueryRow("SELECT COUNT(*) FROM files WHERE listed = 1").Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
SELECT id, owner_id, content_payload_id, metadata_payload_id, content_revision, revision, listed, logical_bytes, physical_bytes, created_at, updated_at
FROM files
WHERE listed = 1
ORDER BY created_at DESC
LIMIT ? OFFSET ?;
`
	rows, err := tx.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []FileRow
	for rows.Next() {
		var f FileRow
		var listedInt int
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.ContentPayloadID, &f.MetadataPayloadID, &f.ContentRevision, &f.Revision, &listedInt, &f.LogicalBytes, &f.PhysicalBytes, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, 0, err
		}
		f.Listed = (listedInt == 1)
		list = append(list, f)
	}
	return list, total, nil
}

func (db *DB) UpdateFileRename(tx *sql.Tx, id, newMetadataPayloadID string, expectedRev, newRev int64, updatedAt string) error {
	query := `
UPDATE files
SET metadata_payload_id = ?, revision = ?, updated_at = ?
WHERE id = ? AND revision = ?;
`
	res, err := tx.Exec(query, newMetadataPayloadID, newRev, updatedAt, id, expectedRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (db *DB) UpdateFileListing(tx *sql.Tx, id string, listed bool, expectedRev, newRev int64, updatedAt string) error {
	query := `
UPDATE files
SET listed = ?, revision = ?, updated_at = ?
WHERE id = ? AND revision = ?;
`
	listedInt := 0
	if listed {
		listedInt = 1
	}
	res, err := tx.Exec(query, listedInt, newRev, updatedAt, id, expectedRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (db *DB) UpdateFileContent(tx *sql.Tx, id, newContentPayloadID, newMetadataPayloadID string, contentRev, expectedRev, newRev int64, logicalBytes, physicalBytes int64, updatedAt string) error {
	// Replacement also deletes grants and sets listed = 0
	if _, err := tx.Exec("DELETE FROM grants WHERE file_id = ?", id); err != nil {
		return err
	}

	query := `
UPDATE files
SET content_payload_id = ?, metadata_payload_id = ?, content_revision = ?, revision = ?, listed = 0, logical_bytes = ?, physical_bytes = ?, updated_at = ?
WHERE id = ? AND revision = ?;
`
	res, err := tx.Exec(query, newContentPayloadID, newMetadataPayloadID, contentRev, newRev, logicalBytes, physicalBytes, updatedAt, id, expectedRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (db *DB) DeleteFile(tx *sql.Tx, id string) error {
	// Fetch file to get payload IDs
	f, err := db.GetFileByID(tx, id)
	if err != nil {
		return err
	}

	// Delete file (cascades to grants)
	if _, err := tx.Exec("DELETE FROM files WHERE id = ?", id); err != nil {
		return err
	}

	// Explicitly delete content and metadata payloads (cascades to variants)
	if _, err := tx.Exec("DELETE FROM payloads WHERE id = ?", f.ContentPayloadID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM payloads WHERE id = ?", f.MetadataPayloadID); err != nil {
		return err
	}

	return nil
}

// Grants methods
func (db *DB) PutGrant(tx *sql.Tx, g GrantRow) error {
	query := `
INSERT INTO grants (file_id, recipient_id, view_metadata, download, created_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(file_id, recipient_id) DO UPDATE SET
view_metadata = excluded.view_metadata,
download = excluded.download;
`
	vm := 0
	if g.ViewMetadata {
		vm = 1
	}
	dl := 0
	if g.Download {
		dl = 1
	}
	_, err := tx.Exec(query, g.FileID, g.RecipientID, vm, dl, g.CreatedAt)
	return err
}

func (db *DB) DeleteGrant(tx *sql.Tx, fileID, recipientID string) error {
	_, err := tx.Exec("DELETE FROM grants WHERE file_id = ? AND recipient_id = ?", fileID, recipientID)
	return err
}

func (db *DB) GetGrant(tx *sql.Tx, fileID, recipientID string) (*GrantRow, error) {
	query := `
SELECT file_id, recipient_id, view_metadata, download, created_at
FROM grants WHERE file_id = ? AND recipient_id = ?;
`
	var g GrantRow
	var vm, dl int
	err := tx.QueryRow(query, fileID, recipientID).Scan(&g.FileID, &g.RecipientID, &vm, &dl, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	g.ViewMetadata = (vm == 1)
	g.Download = (dl == 1)
	return &g, err
}

func (db *DB) GetGrantsForFile(tx *sql.Tx, fileID string) ([]GrantRow, error) {
	query := `
SELECT file_id, recipient_id, view_metadata, download, created_at
FROM grants WHERE file_id = ? ORDER BY created_at ASC;
`
	rows, err := tx.Query(query, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []GrantRow
	for rows.Next() {
		var g GrantRow
		var vm, dl int
		if err := rows.Scan(&g.FileID, &g.RecipientID, &vm, &dl, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.ViewMetadata = (vm == 1)
		g.Download = (dl == 1)
		list = append(list, g)
	}
	return list, nil
}

// Quota methods
func (db *DB) GetUserQuotas(tx *sql.Tx, userID string) (*QuotaUsage, error) {
	query := `
SELECT
    COALESCE(SUM(logical_bytes), 0),
    COALESCE(SUM(physical_bytes), 0),
    COUNT(*)
FROM files
WHERE owner_id = ?;
`
	var u QuotaUsage
	err := tx.QueryRow(query, userID).Scan(&u.LogicalUsedBytes, &u.PhysicalUsedBytes, &u.FileCount)
	if err != nil {
		return nil, err
	}

	// Also add physical footprint of user's profile payload variants
	var profilePhysical int64
	pQuery := `
SELECT COALESCE(SUM(pv.envelope_bytes), 0)
FROM users u
JOIN payload_variants pv ON u.profile_payload_id = pv.payload_id
WHERE u.id = ?;
`
	if err := tx.QueryRow(pQuery, userID).Scan(&profilePhysical); err == nil {
		u.PhysicalUsedBytes += profilePhysical
	}

	return &u, nil
}

