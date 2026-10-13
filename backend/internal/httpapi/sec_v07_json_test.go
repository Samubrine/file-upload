package httpapi

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// V7: JSON bodies are capped at 64 KiB and unknown fields are refused.
func TestV7OversizedJSONBodyRejected(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	anon := &testClient{server: server}
	pad := strings.Repeat("a", 1<<20)
	body := []byte(`{"username":"alice","password":"SecretPassword123!","pad":"` + pad + `"}`)
	w := anon.send(t, "POST", "/auth/login", body, map[string]string{"Content-Type": "application/json"})
	expectStatus(t, w, http.StatusRequestEntityTooLarge, "1 MiB JSON body")
}

func TestV7UnknownFieldRejected(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	anon := &testClient{server: server}
	body := []byte(`{"username":"alice","password":"SecretPassword123!","role":"admin"}`)
	w := anon.send(t, "POST", "/auth/login", body, map[string]string{"Content-Type": "application/json"})
	expectStatus(t, w, http.StatusBadRequest, "JSON with unknown field")

	trailing := bytes.Join([][]byte{[]byte(`{"username":"alice","password":"SecretPassword123!"}`), []byte(`{"x":1}`)}, []byte(" "))
	w = anon.send(t, "POST", "/auth/login", trailing, map[string]string{"Content-Type": "application/json"})
	expectStatus(t, w, http.StatusBadRequest, "JSON with trailing second object")
}
