package httpapi

import (
	"mime"
	"net/http"
	"testing"
)

// V18: the attachment filename uses RFC 6266 encoding so non-ASCII names survive.
func TestV18DispositionEncodesUnicodeFilename(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	name := "résumé 文件.pdf"
	file, _ := alice.uploadFile(t, name, []byte("%PDF-1.4 unicode"), "")

	w := alice.send(t, "GET", "/files/"+file.ID+"/download", nil, nil)
	expectStatus(t, w, http.StatusOK, "download unicode-named file")
	want := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if got := w.Header().Get("Content-Disposition"); got != want {
		t.Fatalf("Content-Disposition = %q; want %q", got, want)
	}
}

// V19: an unknown variant is a client error, and benchmark responses do not
// open cross-origin timing access.
func TestV19UnknownVariantIs400AndNoTimingAllowOrigin(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	file, _ := alice.uploadFile(t, "a.pdf", []byte("%PDF-1.4 variant"), "")

	w := alice.send(t, "GET", "/files/"+file.ID+"/download?variant=bogus", nil, nil)
	expectStatus(t, w, http.StatusBadRequest, "download with unknown variant")

	w = alice.send(t, "GET", "/files/"+file.ID+"/download?variant=aes-256-ctr&benchmark=1", nil, nil)
	expectStatus(t, w, http.StatusOK, "benchmark download")
	if w.Header().Get("Timing-Allow-Origin") != "" {
		t.Fatal("Timing-Allow-Origin must not be sent")
	}
}
