package httpapi

import (
	"fmt"
	"net/http"
	"testing"
)

// V10 over HTTP: renaming to a name with a control character is 422.
func TestV10RenameRejectsControlCharacters(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	file, etag := alice.uploadFile(t, "report.pdf", []byte("%PDF-1.4 rename"), "")

	w := alice.do(t, "PATCH", fmt.Sprintf("/files/%s", file.ID),
		jsonBody(t, RenameInput{Filename: "evil\r\nSet-Cookie: x.pdf"}), "application/json", etag)
	expectStatus(t, w, http.StatusUnprocessableEntity, "rename with CRLF in name")
}
