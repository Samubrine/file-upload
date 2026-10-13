package httpapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"ciphervault/internal/crypto"
	"ciphervault/internal/files"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

// V22 guard: the SPA fallback must never serve a file outside the static dir.
func TestV22StaticTraversalBlocked(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "site")
	if err := os.MkdirAll(site, 0o750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(site, "index.html"), []byte("INDEX"), 0o600)
	os.WriteFile(filepath.Join(root, "secret.txt"), []byte("TOPSECRET"), 0o600)

	db, err := storage.OpenDB(filepath.Join(root, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	kp := crypto.NewMemoryKeyProvider(map[string][]byte{"root-1": bytes.Repeat([]byte{1}, 32)})
	indexKey := bytes.Repeat([]byte{2}, 32)
	uSvc := users.NewService(db, kp, "root-1", indexKey)
	server := NewServer(ServerConfig{DB: db, UsersService: uSvc, FilesService: files.NewService(db, kp, "root-1"),
		SharingService: sharing.NewService(db, indexKey, uSvc.UsernameByID), StaticDir: site})

	anon := &testClient{server: server}
	for _, p := range []string{"/../secret.txt", "/%2e%2e/secret.txt", "/..%5csecret.txt", "/%2e%2e%2fsecret.txt"} {
		w := anon.send(t, "GET", p, nil, nil)
		if bytes.Contains(w.Body.Bytes(), []byte("TOPSECRET")) {
			t.Fatalf("path %s served a file outside the static directory", p)
		}
	}
}
