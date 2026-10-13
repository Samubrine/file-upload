package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// zeroReader yields an endless stream of 'a' bytes and counts how many bytes
// the server actually pulled from it.
type zeroReader struct{ read int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	z.read += int64(len(p))
	return len(p), nil
}

// V8a: a second file part must be refused rather than silently ignored.
func TestV8ExtraFilePartRejected(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")

	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	for _, name := range []string{"one.pdf", "two.pdf"} {
		part, _ := mw.CreateFormFile("file", name)
		_, _ = part.Write([]byte("%PDF-1.4 batch"))
	}
	_ = mw.Close()
	w := alice.send(t, "POST", "/files", buf.Bytes(), map[string]string{
		"Content-Type": mw.FormDataContentType(), "X-CSRF-Token": alice.csrfToken})
	expectStatus(t, w, http.StatusBadRequest, "upload with two file parts")
}

// V8b: an oversized body must be cut off at the cap. The server may not read
// the whole stream into memory or onto disk before rejecting it.
func TestV8OversizedUploadStopsReadingAtCap(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")

	const boundary = "CVBOUNDARY"
	head := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 "
	tail := "\r\n--" + boundary + "--\r\n"
	const payload = int64(200 << 20) // 200 MiB stream
	src := &zeroReader{}
	body := io.MultiReader(strings.NewReader(head), io.LimitReader(src, payload), strings.NewReader(tail))

	req := httptest.NewRequest("POST", "/files", body)
	req.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	req.Header.Set("X-CSRF-Token", alice.csrfToken)
	req.AddCookie(alice.cookie)
	w := httptest.NewRecorder()
	alice.server.ServeHTTP(w, req)

	expectStatus(t, w, http.StatusRequestEntityTooLarge, "200 MiB upload")
	const limit = int64(60 << 20)
	if src.read > limit {
		t.Fatalf("server read %d bytes of a 200 MiB body before rejecting it (limit %d)", src.read, limit)
	}
}
