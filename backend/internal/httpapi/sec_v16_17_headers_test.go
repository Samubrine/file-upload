package httpapi

import (
	"regexp"
	"strings"
	"testing"
)

// V16: every response carries the restrictive Content-Security-Policy.
func TestV16ContentSecurityPolicyPresent(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	anon := &testClient{server: server}
	w := anon.send(t, "GET", "/notice", nil, nil)
	want := "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
	if got := w.Header().Get("Content-Security-Policy"); got != want {
		t.Fatalf("Content-Security-Policy = %q; want %q", got, want)
	}
}

// V17: client-supplied request IDs are used only when they match the safe pattern.
func TestV17RequestIDValidated(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	anon := &testClient{server: server}
	safe := regexp.MustCompile("^[A-Za-z0-9-]{1,64}$")

	for _, bad := range []string{"evil\r\nSet-Cookie: x=1", strings.Repeat("a", 300), "has space", "a;b"} {
		w := anon.send(t, "GET", "/notice", nil, map[string]string{"X-Request-ID": bad})
		got := w.Header().Get("X-Request-ID")
		if got == bad || !safe.MatchString(got) {
			t.Fatalf("hostile request id %q was echoed or not replaced (got %q)", bad, got)
		}
	}
	w := anon.send(t, "GET", "/notice", nil, map[string]string{"X-Request-ID": "trace-123"})
	if got := w.Header().Get("X-Request-ID"); got != "trace-123" {
		t.Fatalf("valid request id not preserved: %q", got)
	}
}
