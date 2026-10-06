package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ciphervault/internal/auth"
	"ciphervault/internal/storage"

	"github.com/google/uuid"
)

type contextKey string

const (
	contextKeyRequestID contextKey = "request_id"
	contextKeySession   contextKey = "session"
)

func GetRequestID(r *http.Request) string {
	if val, ok := r.Context().Value(contextKeyRequestID).(string); ok && val != "" {
		return val
	}
	return ""
}

func GetSession(r *http.Request) *storage.SessionRow {
	if val, ok := r.Context().Value(contextKeySession).(*storage.SessionRow); ok {
		return val
	}
	return nil
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)
		ctx := context.WithValue(r.Context(), contextKeyRequestID, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type SessionAuthMiddleware struct {
	db         *storage.DB
	cookieName string
}

func NewSessionAuthMiddleware(db *storage.DB, cookieName string) *SessionAuthMiddleware {
	return &SessionAuthMiddleware{
		db:         db,
		cookieName: cookieName,
	}
}

func (m *SessionAuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(m.cookieName)
		if err != nil || cookie.Value == "" {
			WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Missing session cookie")
			return
		}

		tokenHash := auth.HashToken(cookie.Value)
		var session *storage.SessionRow
		err = m.db.WithTx(r.Context(), func(tx *sql.Tx) error {
			s, err := m.db.GetSession(tx, tokenHash)
			if err != nil {
				return err
			}
			// Check expiration
			exp, err := time.Parse(time.RFC3339, s.ExpiresAt)
			if err != nil || time.Now().UTC().After(exp) {
				return storage.ErrNotFound
			}
			session = s
			return nil
		})

		if err != nil || session == nil {
			WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired session")
			return
		}

		// CSRF check for state-changing requests
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			csrfHeader := r.Header.Get("X-CSRF-Token")
			if !auth.ValidateCSRF(csrfHeader, session.CSRFTokenHash) {
				WriteError(w, r, http.StatusForbidden, "CSRF_INVALID", "Invalid or missing CSRF token")
				return
			}
		}

		ctx := context.WithValue(r.Context(), contextKeySession, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UploadQueue limits concurrent heavy upload/replace jobs
type UploadQueue struct {
	sem  chan struct{}
	wait sync.Mutex
}

func NewUploadQueue(capacity int) *UploadQueue {
	return &UploadQueue{
		sem: make(chan struct{}, capacity),
	}
}

func (q *UploadQueue) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case q.sem <- struct{}{}:
			defer func() { <-q.sem }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "5")
			WriteError(w, r, http.StatusServiceUnavailable, "BUSY", "Upload queue full, please retry shortly")
		}
	})
}

func ParseIfMatch(header string) (int64, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, errors.New("missing If-Match header")
	}
	// Strip quotes if present (e.g. "1" or 1)
	header = strings.Trim(header, `"`)
	val, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return 0, errors.New("invalid revision in If-Match header")
	}
	return val, nil
}

