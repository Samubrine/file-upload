package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"ciphervault/internal/users"
)

type NoticeResponse struct {
	Version        string `json:"version"`
	Text           string `json:"text"`
	ProjectContact string `json:"project_contact"`
}

type SessionResponse struct {
	CSRFToken string         `json:"csrf_token"`
	ExpiresAt string         `json:"expires_at"`
	User      *users.Profile `json:"user"`
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleNotice(w http.ResponseWriter, r *http.Request) {
	resp := NoticeResponse{
		Version:        users.CurrentNoticeVersion,
		Text:           "CipherVault is an educational encrypted storage system demonstrating multi-cipher evaluations. Passwords are salted Argon2id hashes. File data and user profiles are independently encrypted across 14 cryptographic variants. No password recovery is supported; loss of credentials or root keys results in permanent unrecoverability.",
		ProjectContact: "ciphervault-project@example.edu",
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var input users.RegisterInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	_, profile, rawSession, rawCSRF, err := s.usersService.Register(r.Context(), input)
	if err != nil {
		if err == users.ErrNoticeRequired {
			WriteError(w, r, http.StatusUnprocessableEntity, "NOTICE_REQUIRED", err.Error())
			return
		}
		if err == users.ErrPasswordComplexity {
			WriteError(w, r, http.StatusUnprocessableEntity, "INVALID_PASSWORD", err.Error())
			return
		}
		WriteError(w, r, http.StatusConflict, "REGISTRATION_CONFLICT", err.Error())
		return
	}

	s.setSessionCookie(w, rawSession)
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(SessionResponse{
		CSRFToken: rawCSRF,
		ExpiresAt: expiresAt,
		User:      profile,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var input LoginInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	_, profile, rawSession, rawCSRF, err := s.usersService.Login(r.Context(), input.Username, input.Password)
	if err != nil {
		WriteError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}

	s.setSessionCookie(w, rawSession)
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(SessionResponse{
		CSRFToken: rawCSRF,
		ExpiresAt: expiresAt,
		User:      profile,
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	if session == nil {
		WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Not logged in")
		return
	}

	profile, _, err := s.usersService.GetProfile(r.Context(), session.UserID)
	if err != nil {
		WriteError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "Failed to retrieve user profile")
		return
	}

	// We cannot reverse CSRFTokenHash, so we check if client provided current or pass empty/dummy or session CSRF
	// The client gets the CSRF token from Login/Register responses and stores it in memory.
	// In GET /auth/session, we return the session information.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(SessionResponse{
		CSRFToken: r.Header.Get("X-CSRF-Token"), // echo or current
		ExpiresAt: session.ExpiresAt,
		User:      profile,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	if session != nil {
		_ = s.db.WithTx(r.Context(), func(tx *sql.Tx) error {
			return s.db.DeleteSession(tx, session.TokenHash)
		})
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, rawSession string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    rawSession,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, ) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

