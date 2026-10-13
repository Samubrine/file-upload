package httpapi

import (
	"net/http"
	"testing"
)

// V14: deleting the account must honour If-Match like every other mutation.
func TestV14DeleteAccountChecksRevision(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	body := jsonBody(t, PasswordConfirmInput{CurrentPassword: "SecretPassword123!"})
	w := alice.send(t, "DELETE", "/me", body, map[string]string{
		"Content-Type": "application/json", "X-CSRF-Token": alice.csrfToken, "If-Match": "999"})
	expectStatus(t, w, http.StatusConflict, "delete account with stale If-Match")
	expectStatus(t, alice.send(t, "GET", "/me", nil, nil), http.StatusOK, "account still exists")
}
