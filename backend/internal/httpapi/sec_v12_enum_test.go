package httpapi

import (
	"net/http"
	"sort"
	"testing"
	"time"
)

// V12: a login for an unknown username must cost about as much as a login with a
// wrong password, so response time does not reveal which usernames exist.
func TestV12LoginTimingDoesNotRevealUsers(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	anon := &testClient{server: server}
	h := map[string]string{"Content-Type": "application/json"}

	median := func(user string) time.Duration {
		var ds []time.Duration
		for i := 0; i < 5; i++ {
			body := jsonBody(t, LoginInput{Username: user, Password: "WrongPassword123!"})
			start := time.Now()
			w := anon.send(t, "POST", "/auth/login", body, h)
			ds = append(ds, time.Since(start))
			expectStatus(t, w, http.StatusUnauthorized, "wrong login for "+user)
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	known := median("alice")
	unknown := median("ghost")
	if unknown < known/2 {
		t.Fatalf("unknown-user login took %v, wrong-password login took %v: timing reveals usernames", unknown, known)
	}
}

// V12: a duplicate registration reports one fixed message, not the storage
// conflict text.
func TestV12DuplicateRegistrationMessageIsGeneric(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	anon := &testClient{server: server}
	body := jsonBody(t, map[string]any{"full_name": "Other", "username": "alice", "email": "other@example.com",
		"password": "SecretPassword123!", "notice_version": "1.0", "notice_acknowledged": true})
	w := anon.send(t, "POST", "/auth/register", body, map[string]string{"Content-Type": "application/json"})
	expectStatus(t, w, http.StatusConflict, "duplicate registration")
	msg := decodeBody[ErrorResponse](t, w).Message
	if msg != "username or email unavailable" {
		t.Fatalf("duplicate registration message %q; want the fixed message", msg)
	}
}
