package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ciphervault/internal/crypto"
	"ciphervault/internal/files"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

type testClient struct {
	server       *Server
	cookie       *http.Cookie
	csrfToken    string
	username     string
	userID       string
	etag         string
}

func setupTestServer(t *testing.T) (*Server, *storage.DB) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_api.db")
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}

	rootKeyID := "root-1"
	rootKey := bytes.Repeat([]byte{0x01}, 32)
	indexKey := bytes.Repeat([]byte{0x02}, 32)

	kp := crypto.NewMemoryKeyProvider(map[string][]byte{rootKeyID: rootKey})
	uSvc := users.NewService(db, kp, rootKeyID, indexKey)
	fSvc := files.NewService(db, kp, rootKeyID)
	sSvc := sharing.NewService(db, indexKey)

	server := NewServer(ServerConfig{
		DB:             db,
		UsersService:   uSvc,
		FilesService:   fSvc,
		SharingService: sSvc,
		CookieName:     "ciphervault_session",
		SecureCookies:  false,
		BenchmarkMode:  true,
	})
	return server, db
}

func (c *testClient) register(t *testing.T, fullName, username, email, password string) {
	body, _ := json.Marshal(users.RegisterInput{
		FullName:           fullName,
		Username:           username,
		Email:              email,
		Password:           password,
		NoticeVersion:      "1.0",
		NoticeAcknowledged: true,
	})

	req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	c.server.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register failed with status %d: %s", w.Code, w.Body.String())
	}

	for _, ck := range w.Result().Cookies() {
		if ck.Name == "ciphervault_session" {
			c.cookie = ck
		}
	}
	if c.cookie == nil {
		t.Fatalf("expected session cookie on register")
	}

	var resp SessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	c.csrfToken = resp.CSRFToken
	c.username = username
}

func (c *testClient) do(t *testing.T, method, path string, body []byte, contentType string, ifMatch string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}

	w := httptest.NewRecorder()
	c.server.ServeHTTP(w, req)
	if etag := w.Header().Get("ETag"); etag != "" {
		c.etag = etag
	}
	return w
}

func (c *testClient) uploadFile(t *testing.T, filename string, content []byte, category string) (*files.OwnerFileDTO, string) {
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)

	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if category != "" {
		_ = mw.WriteField("category", category)
	}
	_ = mw.Close()

	w := c.do(t, "POST", "/files", buf.Bytes(), mw.FormDataContentType(), "")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload failed with %d: %s", w.Code, w.Body.String())
	}

	var dto files.OwnerFileDTO
	if err := json.NewDecoder(w.Body).Decode(&dto); err != nil {
		t.Fatal(err)
	}
	return &dto, w.Header().Get("ETag")
}

func TestEndToEndPermissionsAndLifecycle(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	// 1. Notice endpoint
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/notice", nil)
	server.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("notice failed with status %d", w.Code)
	}

	// 2. Register users
	clientA := &testClient{server: server}
	clientA.register(t, "Alice Owner", "alice", "alice@example.com", "SecretPassword123!")

	clientB := &testClient{server: server}
	clientB.register(t, "Bob Metadata", "bob", "bob@example.com", "SecretPassword123!")

	clientC := &testClient{server: server}
	clientC.register(t, "Charlie Download", "charlie", "charlie@example.com", "SecretPassword123!")

	clientD := &testClient{server: server}
	clientD.register(t, "David Unrelated", "david", "david@example.com", "SecretPassword123!")

	visitor := &testClient{server: server} // Unauthenticated

	// 3. Upload file by Alice (PDF document)
	pdfContent := []byte("%PDF-1.4 sample pdf content for testing encryption across 14 variants")
	fileDTO, fileEtag := clientA.uploadFile(t, "report.pdf", pdfContent, "document")
	fileID := fileDTO.ID

	if len(fileDTO.Variants) != 14 {
		t.Fatalf("expected 14 variants, got %d", len(fileDTO.Variants))
	}

	// 4. Test Hidden File State
	// - Visitor cannot list homepage
	w = visitor.do(t, "GET", "/files/listed", nil, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected visitor to be denied homepage, got %d", w.Code)
	}

	// - David (unrelated) cannot discover hidden file
	w = clientD.do(t, "GET", fmt.Sprintf("/files/%s", fileID), nil, "", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unrelated user on hidden file, got %d", w.Code)
	}

	// - David cannot download hidden file
	w = clientD.do(t, "GET", fmt.Sprintf("/files/%s/download", fileID), nil, "", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 download for unrelated user on hidden file, got %d", w.Code)
	}

	// 5. Grant metadata-only to Bob
	grantBody, _ := json.Marshal(GrantSetInput{ViewMetadata: true, Download: false})
	w = clientA.do(t, "PUT", fmt.Sprintf("/files/%s/grants/bob", fileID), grantBody, "application/json", fileEtag)
	if w.Code != http.StatusOK {
		t.Fatalf("grant to bob failed: %d %s", w.Code, w.Body.String())
	}
	fileEtag = w.Header().Get("ETag")

	// - Bob can now view metadata (filename + owner)
	w = clientB.do(t, "GET", fmt.Sprintf("/files/%s", fileID), nil, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("bob view metadata failed: %d", w.Code)
	}
	var metaDTO files.MetadataDTO
	if err := json.NewDecoder(w.Body).Decode(&metaDTO); err != nil {
		t.Fatal(err)
	}
	if metaDTO.Filename != "report.pdf" || metaDTO.OwnerUsername != "alice" {
		t.Errorf("metadata mismatch: %+v", metaDTO)
	}

	// - Bob is FORBIDDEN from downloading
	w = clientB.do(t, "GET", fmt.Sprintf("/files/%s/download", fileID), nil, "", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 forbidden for metadata-only recipient download, got %d", w.Code)
	}

	// - Bob cannot manage (rename/delete)
	renameBody, _ := json.Marshal(RenameInput{Filename: "hacked.pdf"})
	w = clientB.do(t, "PATCH", fmt.Sprintf("/files/%s", fileID), renameBody, "application/json", fileEtag)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 when recipient tries to rename, got %d", w.Code)
	}

	// 6. Grant download to Charlie
	grantBody, _ = json.Marshal(GrantSetInput{ViewMetadata: true, Download: true})
	w = clientA.do(t, "PUT", fmt.Sprintf("/files/%s/grants/charlie", fileID), grantBody, "application/json", fileEtag)
	if w.Code != http.StatusOK {
		t.Fatalf("grant to charlie failed: %d %s", w.Code, w.Body.String())
	}
	fileEtag = w.Header().Get("ETag")

	// - Charlie can download across all 14 variants and verify byte-identical plaintext
	for _, vID := range crypto.AllVariantIDs {
		w = clientC.do(t, "GET", fmt.Sprintf("/files/%s/download?variant=%s", fileID, vID), nil, "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("charlie download variant %s failed with %d: %s", vID, w.Code, w.Body.String())
		}
		if !bytes.Equal(w.Body.Bytes(), pdfContent) {
			t.Fatalf("charlie downloaded bytes mismatch for variant %s", vID)
		}
		// Verify Server-Timing header is emitted in benchmark mode
		if st := w.Header().Get("Server-Timing"); st == "" {
			t.Errorf("expected Server-Timing header in benchmark mode for variant %s", vID)
		}
	}

	// 7. Toggle Public Listing
	listBody, _ := json.Marshal(ListingInput{Listed: true})
	w = clientA.do(t, "PUT", fmt.Sprintf("/files/%s/listing", fileID), listBody, "application/json", fileEtag)
	if w.Code != http.StatusOK {
		t.Fatalf("listing toggle failed: %d", w.Code)
	}
	fileEtag = w.Header().Get("ETag")

	// - Now David (unrelated authenticated) sees file on listed homepage
	w = clientD.do(t, "GET", "/files/listed", nil, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("david list homepage failed: %d", w.Code)
	}
	var pageResp MetadataPageResponse
	if err := json.NewDecoder(w.Body).Decode(&pageResp); err != nil {
		t.Fatal(err)
	}
	if len(pageResp.Items) != 1 || pageResp.Items[0].Filename != "report.pdf" {
		t.Errorf("unexpected homepage listed items: %+v", pageResp)
	}

	// - BUT David is still FORBIDDEN from downloading! (Listing alone does NOT grant download)
	w = clientD.do(t, "GET", fmt.Sprintf("/files/%s/download", fileID), nil, "", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 download for listed unrelated user, got %d", w.Code)
	}

	// 8. Rename file by Alice
	renameBody, _ = json.Marshal(RenameInput{Filename: "annual_report.pdf"})
	w = clientA.do(t, "PATCH", fmt.Sprintf("/files/%s", fileID), renameBody, "application/json", fileEtag)
	if w.Code != http.StatusOK {
		t.Fatalf("rename failed: %d %s", w.Code, w.Body.String())
	}
	fileEtag = w.Header().Get("ETag")

	// - Charlie still has download access after rename
	w = clientC.do(t, "GET", fmt.Sprintf("/files/%s/download", fileID), nil, "", "")
	if w.Code != http.StatusOK {
		t.Errorf("expected charlie download to succeed after rename, got %d", w.Code)
	}

	// 9. Replace file content by Alice
	newPdfContent := []byte("%PDF-1.4 brand new replaced content for file revision 2")
	buf := new(bytes.Buffer)
	mw := multipart.NewWriter(buf)
	part, _ := mw.CreateFormFile("file", "annual_report.pdf")
	_, _ = part.Write(newPdfContent)
	_ = mw.Close()

	w = clientA.do(t, "PUT", fmt.Sprintf("/files/%s/content", fileID), buf.Bytes(), mw.FormDataContentType(), fileEtag)
	if w.Code != http.StatusOK {
		t.Fatalf("replace failed: %d %s", w.Code, w.Body.String())
	}
	fileEtag = w.Header().Get("ETag")

	// Replacement MUST revoke grants and reset listed=false!
	// - Charlie should now be DENIED (404 Not Found since file is also unlisted)
	w = clientC.do(t, "GET", fmt.Sprintf("/files/%s/download", fileID), nil, "", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected charlie download to be revoked after replacement, got %d", w.Code)
	}

	// - David should not see it on homepage
	w = clientD.do(t, "GET", "/files/listed", nil, "", "")
	var pageResp2 MetadataPageResponse
	_ = json.NewDecoder(w.Body).Decode(&pageResp2)
	if len(pageResp2.Items) != 0 {
		t.Errorf("expected file to be unlisted after replacement, but found %d items", len(pageResp2.Items))
	}

	// 10. Delete file
	w = clientA.do(t, "DELETE", fmt.Sprintf("/files/%s", fileID), nil, "", fileEtag)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete file failed: %d", w.Code)
	}

	// Verify file is gone for Alice
	w = clientA.do(t, "GET", fmt.Sprintf("/files/%s", fileID), nil, "", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 after file delete, got %d", w.Code)
	}
}

