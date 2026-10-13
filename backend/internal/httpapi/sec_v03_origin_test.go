package httpapi

import (
	"net/http"
	"testing"
)

// V3: browsers attach Origin / Sec-Fetch-Site to cross-site requests. Mutating
// requests from another origin must be refused, including login and register
// (login CSRF) and authenticated calls that carry a valid CSRF token.
func TestV3CrossSiteMutationsRejected(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	login := jsonBody(t, LoginInput{Username: "alice", Password: "SecretPassword123!"})
	evil := map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}

	anon := &testClient{server: server}
	expectStatus(t, anon.send(t, "POST", "/auth/login", login, evil), http.StatusForbidden, "cross-site login")

	reg := jsonBody(t, map[string]any{"full_name": "Mallory", "username": "mallory", "email": "m@example.com",
		"password": "SecretPassword123!", "notice_version": "1.0", "notice_acknowledged": true})
	expectStatus(t, anon.send(t, "POST", "/auth/register", reg, evil), http.StatusForbidden, "cross-site register")

	expectStatus(t, anon.send(t, "POST", "/auth/login", login, map[string]string{
		"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "Sec-Fetch-Site cross-site login")

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	expectStatus(t, alice.send(t, "POST", "/auth/logout", nil, map[string]string{
		"X-CSRF-Token": alice.csrfToken, "Origin": "https://evil.example"}), http.StatusForbidden, "cross-site logout with valid CSRF")
}

func TestV3SameOriginAndOriginlessRequestsAllowed(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	anon := &testClient{server: server}
	login := jsonBody(t, LoginInput{Username: "nobody", Password: "SecretPassword123!"})
	for _, h := range []map[string]string{
		{"Content-Type": "application/json", "Origin": "http://localhost:8080"},
		{"Content-Type": "application/json", "Origin": "http://example.com"}, // httptest request host
		{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"},
		{"Content-Type": "application/json"},
	} {
		w := anon.send(t, "POST", "/auth/login", login, h)
		if w.Code == http.StatusForbidden {
			t.Fatalf("same-origin login rejected with headers %v: %s", h, w.Body.String())
		}
	}
}
