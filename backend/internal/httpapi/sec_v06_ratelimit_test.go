package httpapi

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// freezeLimiterClock stops the bucket clock. Bcrypt under the race detector can
// take seconds per attempt, which would refill tokens mid-test and make the
// counts depend on machine speed.
func freezeLimiterClock(server *Server) {
	frozen := time.Now()
	server.limiter.now = func() time.Time { return frozen }
}

// V6: login, register and grant changes must be rate limited. Responses over
// the limit use 429 with a Retry-After header.
func TestV6LoginRateLimited(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	freezeLimiterClock(server)

	anon := &testClient{server: server}
	bad := jsonBody(t, LoginInput{Username: "alice", Password: "WrongPassword123!"})
	h := map[string]string{"Content-Type": "application/json"}
	for i := 1; i <= 10; i++ {
		w := anon.send(t, "POST", "/auth/login", bad, h)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was limited too early", i)
		}
	}
	w := anon.send(t, "POST", "/auth/login", bad, h)
	expectStatus(t, w, http.StatusTooManyRequests, "11th login attempt in one minute")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 response must include Retry-After")
	}
}

func TestV6RegisterRateLimitedPerIP(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	freezeLimiterClock(server)

	anon := &testClient{server: server}
	h := map[string]string{"Content-Type": "application/json"}
	for i := 1; i <= 5; i++ {
		body := jsonBody(t, map[string]any{"full_name": "User", "username": fmt.Sprintf("user%d", i),
			"email": fmt.Sprintf("user%d@example.com", i), "password": "SecretPassword123!",
			"notice_version": "1.0", "notice_acknowledged": true})
		expectStatus(t, anon.send(t, "POST", "/auth/register", body, h), http.StatusCreated, fmt.Sprintf("register %d", i))
	}
	body := jsonBody(t, map[string]any{"full_name": "User", "username": "user6",
		"email": "user6@example.com", "password": "SecretPassword123!",
		"notice_version": "1.0", "notice_acknowledged": true})
	w := anon.send(t, "POST", "/auth/register", body, h)
	expectStatus(t, w, http.StatusTooManyRequests, "6th registration from same IP")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 response must include Retry-After")
	}
}

func TestV6GrantChangesRateLimitedPerUser(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()
	freezeLimiterClock(server)

	alice := &testClient{server: server}
	alice.register(t, "Alice", "alice", "alice@example.com", "SecretPassword123!")
	file, etag := alice.uploadFile(t, "a.pdf", []byte("%PDF-1.4 rate"), "")

	for i := 1; i <= 30; i++ {
		w := alice.do(t, "PUT", fmt.Sprintf("/files/%s/grants/nobody", file.ID),
			jsonBody(t, GrantSetInput{ViewMetadata: true}), "application/json", "")
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("grant change %d was limited too early", i)
		}
	}
	w := alice.do(t, "PUT", fmt.Sprintf("/files/%s/grants/nobody", file.ID),
		jsonBody(t, GrantSetInput{ViewMetadata: true}), "application/json", etag)
	expectStatus(t, w, http.StatusTooManyRequests, "31st grant change in one minute")
}

