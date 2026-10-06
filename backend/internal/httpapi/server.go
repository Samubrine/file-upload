package httpapi

import (
	"net/http"
	"os"
	"path/filepath"

	"ciphervault/internal/files"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
	"ciphervault/internal/users"
)

type ServerConfig struct {
	DB             *storage.DB
	UsersService   *users.Service
	FilesService   *files.Service
	SharingService *sharing.Service
	CookieName     string
	SecureCookies  bool
	BenchmarkMode  bool
	StaticDir      string
}

type Server struct {
	db             *storage.DB
	usersService   *users.Service
	filesService   *files.Service
	sharingService *sharing.Service
	cookieName     string
	secureCookies  bool
	benchmarkMode  bool
	staticDir      string
	uploadQueue    *UploadQueue
	handler        http.Handler
}

func NewServer(cfg ServerConfig) *Server {
	if cfg.CookieName == "" {
		cfg.CookieName = "ciphervault_session"
	}

	s := &Server{
		db:             cfg.DB,
		usersService:   cfg.UsersService,
		filesService:   cfg.FilesService,
		sharingService: cfg.SharingService,
		cookieName:     cfg.CookieName,
		secureCookies:  cfg.SecureCookies,
		benchmarkMode:  cfg.BenchmarkMode,
		staticDir:      cfg.StaticDir,
		uploadQueue:    NewUploadQueue(2), // 2-job queue for upload serialization
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	mux := http.NewServeMux()
	authMiddleware := NewSessionAuthMiddleware(s.db, s.cookieName)

	// Public routes
	mux.HandleFunc("GET /notice", s.handleNotice)
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("GET /crypto/variants", s.handleGetVariants)

	// Authenticated routes
	authed := func(pattern string, handler http.HandlerFunc) {
		mux.Handle(pattern, authMiddleware.RequireAuth(handler))
	}

	authed("GET /auth/session", s.handleGetSession)
	authed("POST /auth/logout", s.handleLogout)

	authed("GET /me", s.handleGetMe)
	authed("PATCH /me", s.handlePatchMe)
	authed("DELETE /me", s.handleDeleteMe)
	authed("PUT /me/password", s.handlePutPassword)
	authed("GET /me/export", s.handleExportMe)
	authed("GET /me/quota", s.handleGetQuota)

	mux.Handle("POST /files", authMiddleware.RequireAuth(s.uploadQueue.Limit(http.HandlerFunc(s.handleUpload))))
	authed("GET /files/mine", s.handleListMine)
	authed("GET /files/shared", s.handleListShared)
	authed("GET /files/listed", s.handleListListed)
	authed("GET /files/{file_id}", s.handleGetFile)
	authed("PATCH /files/{file_id}", s.handleRenameFile)
	authed("DELETE /files/{file_id}", s.handleDeleteFile)
	mux.Handle("PUT /files/{file_id}/content", authMiddleware.RequireAuth(s.uploadQueue.Limit(http.HandlerFunc(s.handleReplaceContent))))
	authed("PUT /files/{file_id}/listing", s.handleSetListing)
	authed("GET /files/{file_id}/grants", s.handleGetGrants)
	authed("PUT /files/{file_id}/grants/{username}", s.handlePutGrant)
	authed("DELETE /files/{file_id}/grants/{username}", s.handleDeleteGrant)
	authed("GET /files/{file_id}/download", s.handleDownload)

	// Static SPA fallback
	if s.staticDir != "" {
		fileServer := http.FileServer(http.Dir(s.staticDir))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Join(s.staticDir, filepath.Clean(r.URL.Path))
			info, err := os.Stat(path)
			if err == nil && !info.IsDir() {
				fileServer.ServeHTTP(w, r)
				return
			}
			// If not found, serve index.html for client-side routing
			indexPath := filepath.Join(s.staticDir, "index.html")
			if _, err := os.Stat(indexPath); err == nil {
				http.ServeFile(w, r, indexPath)
				return
			}
			http.NotFound(w, r)
		})
	}

	// Chain global middleware: RequestID -> SecurityHeaders -> Router
	s.handler = RequestIDMiddleware(SecurityHeadersMiddleware(mux))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

