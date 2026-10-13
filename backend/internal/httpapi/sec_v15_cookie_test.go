package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ciphervault/internal/crypto"
	"ciphervault/internal/files"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

// V15: with secure cookies on, the session cookie uses the __Host- prefix,
// Secure, HttpOnly and SameSite=Strict, and HSTS is sent.
func TestV15SecureCookieAttributes(t *testing.T) {
	db, err := storage.OpenDB(filepath.Join(t.TempDir(), "secure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rootKeyID := "root-1"
	kp := crypto.NewMemoryKeyProvider(map[string][]byte{rootKeyID: bytes.Repeat([]byte{1}, 32)})
	indexKey := bytes.Repeat([]byte{2}, 32)
	uSvc := users.NewService(db, kp, rootKeyID, indexKey)
	server := NewServer(ServerConfig{
		DB: db, UsersService: uSvc, FilesService: files.NewService(db, kp, rootKeyID),
		SharingService: sharing.NewService(db, indexKey, uSvc.UsernameByID),
		CookieName: "ciphervault_session", SecureCookies: true, PublicOrigin: "https://ciphervault.example",
	})

	body := jsonBody(t, map[string]any{"full_name": "Alice", "username": "alice", "email": "alice@example.com",
		"password": "SecretPassword123!", "notice_version": "1.0", "notice_acknowledged": true})
	req := httptest.NewRequest("POST", "https://ciphervault.example/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	expectStatus(t, w, http.StatusCreated, "secure register")

	var found *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "__Host-ciphervault_session" {
			found = ck
		}
	}
	if found == nil {
		t.Fatalf("expected cookie named __Host-ciphervault_session, got %v", w.Result().Cookies())
	}
	if !found.Secure || !found.HttpOnly || found.SameSite != http.SameSiteStrictMode || found.Path != "/" {
		t.Fatalf("cookie attributes wrong: secure=%v httponly=%v samesite=%v path=%q", found.Secure, found.HttpOnly, found.SameSite, found.Path)
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("Strict-Transport-Security header missing on secure deployment")
	}
}
