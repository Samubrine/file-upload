package httpapi

import (
	"net/http"
	"testing"
)

// V2: after a page reload the browser only has its session cookie. GET
// /auth/session must hand back a CSRF token that authorizes later mutations.
func TestV2SessionRestoreIssuesUsableCSRFToken(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")

	reloaded := &testClient{server: server, cookie: alice.cookie}
	w := reloaded.send(t, "GET", "/auth/session", nil, nil)
	expectStatus(t, w, http.StatusOK, "GET /auth/session")
	sess := decodeBody[SessionResponse](t, w)
	if sess.CSRFToken == "" {
		t.Fatal("GET /auth/session returned an empty CSRF token; a reloaded client cannot mutate anything")
	}

	w = reloaded.send(t, "POST", "/auth/logout", nil, map[string]string{"X-CSRF-Token": sess.CSRFToken})
	expectStatus(t, w, http.StatusNoContent, "logout with restored CSRF token")
}

// Attacker-supplied X-CSRF-Token headers must never be echoed back as valid.
func TestV2SessionDoesNotEchoRequestCSRFHeader(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")

	reloaded := &testClient{server: server, cookie: alice.cookie}
	w := reloaded.send(t, "GET", "/auth/session", nil, map[string]string{"X-CSRF-Token": "attacker-chosen"})
	sess := decodeBody[SessionResponse](t, w)
	if sess.CSRFToken == "attacker-chosen" {
		t.Fatal("GET /auth/session echoed the request's X-CSRF-Token header")
	}
}
