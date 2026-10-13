package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"ciphervault/internal/auth"
)

// V4: bcrypt only reads the first 72 bytes. Passwords longer than that must be
// rejected, otherwise any suffix authenticates.
func TestV4LongPasswordsRejected(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	long := strings.Repeat("a", 90) + "UniqueSuffix" // 102 bytes, 102 runes
	anon := &testClient{server: server}
	reg := jsonBody(t, map[string]any{"full_name": "Long", "username": "longpw", "email": "l@example.com",
		"password": long, "notice_version": "1.0", "notice_acknowledged": true})
	w := anon.send(t, "POST", "/auth/register", reg, map[string]string{"Content-Type": "application/json"})
	if w.Code == http.StatusCreated {
		other := strings.Repeat("a", 90) + "TotallyDifferent"
		lw := anon.send(t, "POST", "/auth/login", jsonBody(t, LoginInput{Username: "longpw", Password: other}),
			map[string]string{"Content-Type": "application/json"})
		if lw.Code == http.StatusOK {
			t.Fatal("a different password sharing the first 72 bytes logged in")
		}
	}
	expectStatus(t, w, http.StatusUnprocessableEntity, "register with 102-byte password")

	emoji := strings.Repeat("\U0001F510", 20) // 20 runes, 80 bytes
	reg = jsonBody(t, map[string]any{"full_name": "Emoji", "username": "emojipw", "email": "e@example.com",
		"password": emoji, "notice_version": "1.0", "notice_acknowledged": true})
	expectStatus(t, anon.send(t, "POST", "/auth/register", reg, map[string]string{"Content-Type": "application/json"}),
		http.StatusUnprocessableEntity, "register with 80-byte multibyte password")

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	me := alice.send(t, "GET", "/me", nil, nil)
	change := jsonBody(t, map[string]string{"current_password": "SecretPassword123!", "new_password": long})
	expectStatus(t, alice.send(t, "PUT", "/me/password", change, map[string]string{
		"Content-Type": "application/json", "X-CSRF-Token": alice.csrfToken, "If-Match": me.Header().Get("ETag")}),
		http.StatusUnprocessableEntity, "password change to 102-byte password")
}

func TestV4VerifyRejectsOverlongCandidate(t *testing.T) {
	prefix := strings.Repeat("b", 72)
	hash, err := auth.HashPassword(prefix)
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := auth.VerifyPassword(prefix+"anything", hash)
	if ok {
		t.Fatal("VerifyPassword accepted a password longer than 72 bytes")
	}
	if _, err := auth.HashPassword(prefix + "x"); err == nil {
		t.Fatal("HashPassword must refuse passwords longer than 72 bytes instead of truncating")
	}
}
