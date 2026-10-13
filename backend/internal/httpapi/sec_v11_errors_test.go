package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// V11: a storage failure must surface as a fixed generic message. The database
// error text must never reach the client.
func TestV11StorageFailureReturnsGenericMessage(t *testing.T) {
	server, db := setupTestServer(t)
	db.Close()

	anon := &testClient{server: server}
	body := jsonBody(t, map[string]any{"full_name": "Eve", "username": "eve", "email": "eve@example.com",
		"password": "SecretPassword123!", "notice_version": "1.0", "notice_acknowledged": true})
	w := anon.send(t, "POST", "/auth/register", body, map[string]string{"Content-Type": "application/json"})
	expectStatus(t, w, http.StatusInternalServerError, "register with unavailable database")
	for _, leak := range []string{"sql", "closed", "database"} {
		if strings.Contains(strings.ToLower(w.Body.String()), leak) {
			t.Fatalf("internal error text leaked to client (%q): %s", leak, w.Body.String())
		}
	}
}

func TestV11ConflictMessageHasNoInternals(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	file, _ := alice.uploadFile(t, "a.pdf", []byte("%PDF-1.4 conflict"), "")

	w := alice.do(t, "DELETE", "/files/"+file.ID, nil, "", "999")
	expectStatus(t, w, http.StatusConflict, "delete with stale revision")
	if strings.Contains(w.Body.String(), "optimistic") || strings.Contains(w.Body.String(), "constraint") {
		t.Fatalf("storage conflict text leaked to client: %s", w.Body.String())
	}
}
