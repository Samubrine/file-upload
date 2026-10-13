// Command smoke drives a running CipherVault server over HTTP: register with an
// Origin header, restore the session after a reload, upload, share, download every
// variant as the recipient, revoke, and confirm cross-site requests are refused.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
)

type client struct {
	base   string
	http   *http.Client
	csrf   string
	origin string
}

type sessionBody struct {
	CSRFToken string "json:\"csrf_token\""
}

type fileBody struct {
	ID       string   "json:\"id\""
	Variants []string "json:\"variants\""
}

func newClient(base string, jar http.CookieJar) *client {
	if jar == nil {
		jar, _ = cookiejar.New(nil)
	}
	return &client{base: base, http: &http.Client{Jar: jar}, origin: base}
}

func (c *client) do(method, path string, body []byte, contentType string, headers map[string]string) (int, http.Header, []byte) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	must(err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Origin", c.origin)
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	must(err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Printf("FAIL "+format+"\n", args...)
	os.Exit(1)
}

func expect(cond bool, format string, args ...any) {
	if !cond {
		fail(format, args...)
	}
	fmt.Printf("ok   "+format+"\n", args...)
}

func jsonOf(b []byte, v any) {
	if err := json.Unmarshal(b, v); err != nil {
		fail("decode %s: %v", string(b), err)
	}
}

const password = "SmokeTest-Passphrase-1"

func register(c *client, username string) {
	body, _ := json.Marshal(map[string]any{"full_name": strings.ToUpper(username[:1]) + username[1:],
		"username": username, "email": username + "@example.com", "password": password,
		"notice_version": "1.0", "notice_acknowledged": true})
	status, _, b := c.do(http.MethodPost, "/auth/register", body, "application/json", nil)
	expect(status == http.StatusCreated, "register %s with Origin header -> %d", username, status)
	var s sessionBody
	jsonOf(b, &s)
	c.csrf = s.CSRFToken
}

func main() {
	base := flag.String("base", "http://localhost:8097", "server base URL (must match -public-origin)")
	flag.Parse()
	suffix := fmt.Sprint(os.Getpid())

	owner := newClient(*base, nil)
	recipient := newClient(*base, nil)
	owner.origin = *base
	recipient.origin = *base
	owner.origin = *base
	register(owner, "smokeowner"+suffix)

	// Reload: a new client that holds only the session cookie.
	reloaded := newClient(*base, owner.http.Jar)
	status, _, b := reloaded.do(http.MethodGet, "/auth/session", nil, "", nil)
	expect(status == http.StatusOK, "reload restores the session -> %d", status)
	var s sessionBody
	jsonOf(b, &s)
	expect(s.CSRFToken != "", "reload issues a usable CSRF token")
	owner.csrf = s.CSRFToken

	content := []byte("%PDF-1.4 smoke test document " + suffix)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, _ := mw.CreateFormFile("file", "smoke.pdf")
	_, _ = part.Write(content)
	_ = mw.Close()
	status, hdr, b := owner.do(http.MethodPost, "/files", buf.Bytes(), mw.FormDataContentType(), nil)
	expect(status == http.StatusCreated, "owner uploads smoke.pdf -> %d", status)
	var f fileBody
	jsonOf(b, &f)
	etag := hdr.Get("ETag")
	expect(len(f.Variants) == 6, "upload reports 6 variants")

	register(recipient, "smokerecipient"+suffix)

	grant := []byte("{\"view_metadata\":true,\"download\":true}")
	status, hdr, _ = owner.do(http.MethodPut, "/files/"+f.ID+"/grants/smokerecipient"+suffix, grant, "application/json", map[string]string{"If-Match": etag})
	expect(status == http.StatusOK, "owner grants download to recipient -> %d", status)
	etag = hdr.Get("ETag")

	want := sha256.Sum256(content)
	for _, v := range f.Variants {
		status, _, got := recipient.do(http.MethodGet, "/files/"+f.ID+"/download?variant="+v, nil, "", nil)
		expect(status == http.StatusOK && sha256.Sum256(got) == want, "recipient downloads %s byte-identical", v)
	}

	status, _, _ = owner.do(http.MethodDelete, "/files/"+f.ID+"/grants/smokerecipient"+suffix, nil, "", map[string]string{"If-Match": etag})
	expect(status == http.StatusOK, "owner revokes recipient -> %d", status)
	status, _, _ = recipient.do(http.MethodGet, "/files/"+f.ID+"/download?variant=aes-256-ctr", nil, "", nil)
	expect(status == http.StatusNotFound, "revoked recipient cannot download -> %d", status)

	login := []byte(fmt.Sprintf("{\"username\":\"smokeowner%s\",\"password\":\"%s\"}", suffix, password))
	status, _, _ = owner.do(http.MethodPost, "/auth/login", login, "application/json", map[string]string{"Origin": "https://evil.example"})
	expect(status == http.StatusForbidden, "cross-site login refused -> %d", status)
	listing := []byte("{\"listed\":true}")
	status, _, _ = owner.do(http.MethodPut, "/files/"+f.ID+"/listing", listing, "application/json", map[string]string{"Origin": "https://evil.example", "If-Match": etag, "Sec-Fetch-Site": "cross-site"})
	expect(status == http.StatusForbidden, "cross-site listing change refused -> %d", status)

	fmt.Println(strings.Repeat("-", 20), "smoke test passed")
}
