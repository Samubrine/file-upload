package storage

import (
	"path/filepath"
	"testing"
)

// V20: expired sessions are removed when the database is opened (process start).
func TestV20ExpiredSessionsPurgedOnStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge.db")
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	mustExec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO payloads (id, kind, context_owner_id, content_revision, created_at) VALUES ('p1','profile','u1',1,'2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO users (id, username_lookup, email_lookup, password_hash, profile_payload_id, revision, created_at) VALUES ('u1', x'01', x'02', 'h', 'p1', 1, '2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO sessions (token_hash, user_id, csrf_token_hash, created_at, expires_at) VALUES (x'aa','u1',x'bb','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`)
	mustExec(`INSERT INTO sessions (token_hash, user_id, csrf_token_hash, created_at, expires_at) VALUES (x'cc','u1',x'dd','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z')`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected only the unexpired session to remain after startup, found %d", n)
	}
}
