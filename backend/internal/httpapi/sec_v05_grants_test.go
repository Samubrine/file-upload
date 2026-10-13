package httpapi

import (
	"fmt"
	"net/http"
	"testing"

	"ciphervault/internal/sharing"
)

// V5: the owner's grant list must show recipient usernames, never internal
// user IDs, and the listed name must work for revocation.
func TestV5GrantListShowsUsernames(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	bob := &testClient{server: server}
	bob.register(t, "Bob", "bob", "bob@example.com", "SecretPassword123!")

	file, etag := alice.uploadFile(t, "notes.pdf", []byte("%PDF-1.4 grant test"), "")
	w := alice.do(t, "PUT", fmt.Sprintf("/files/%s/grants/bob", file.ID),
		jsonBody(t, GrantSetInput{ViewMetadata: true, Download: true}), "application/json", etag)
	expectStatus(t, w, http.StatusOK, "grant bob")
	etag = w.Header().Get("ETag")

	w = alice.send(t, "GET", fmt.Sprintf("/files/%s/grants", file.ID), nil, nil)
	expectStatus(t, w, http.StatusOK, "list grants")
	grants := decodeBody[[]sharing.GrantDTO](t, w)
	if len(grants) != 1 || grants[0].RecipientUsername != "bob" {
		t.Fatalf("expected one grant for \"bob\", got %+v", grants)
	}

	w = alice.do(t, "DELETE", fmt.Sprintf("/files/%s/grants/%s", file.ID, grants[0].RecipientUsername), nil, "", etag)
	expectStatus(t, w, http.StatusOK, "revoke using listed username")
}
