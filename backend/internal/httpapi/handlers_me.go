package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ciphervault/internal/users"
)

type PasswordChangeInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type PasswordConfirmInput struct {
	CurrentPassword string `json:"current_password"`
}

type QuotaResponse struct {
	LogicalUsedBytes   int64 `json:"logical_used_bytes"`
	LogicalLimitBytes  int64 `json:"logical_limit_bytes"`
	PhysicalUsedBytes  int64 `json:"physical_used_bytes"`
	PhysicalLimitBytes int64 `json:"physical_limit_bytes"`
	FileCount          int64 `json:"file_count"`
	FileCountLimit     int64 `json:"file_count_limit"`
}

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	profile, rev, err := s.usersService.GetProfile(r.Context(), session.UserID)
	if err != nil {
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "Profile not found")
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(rev, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(profile)
}

func (s *Server) handlePatchMe(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input users.ProfileUpdateInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	updated, newRev, err := s.usersService.UpdateProfile(r.Context(), session.UserID, expectedRev, input)
	if err != nil {
		if err == users.ErrPasswordMismatch {
			WriteError(w, r, http.StatusForbidden, "PASSWORD_MISMATCH", "Incorrect current password")
			return
		}
		WriteError(w, r, http.StatusConflict, "UPDATE_CONFLICT", err.Error())
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(newRev, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(updated)
}

func (s *Server) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	_, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input PasswordConfirmInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	if err := s.usersService.DeleteAccount(r.Context(), session.UserID, input.CurrentPassword); err != nil {
		if err == users.ErrPasswordMismatch {
			WriteError(w, r, http.StatusForbidden, "PASSWORD_MISMATCH", "Incorrect current password")
			return
		}
		WriteError(w, r, http.StatusInternalServerError, "DELETE_ERROR", err.Error())
		return
	}

	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePutPassword(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input PasswordChangeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	if err := s.usersService.UpdatePassword(r.Context(), session.UserID, expectedRev, input.CurrentPassword, input.NewPassword, session.TokenHash); err != nil {
		if err == users.ErrPasswordMismatch {
			WriteError(w, r, http.StatusForbidden, "PASSWORD_MISMATCH", "Incorrect current password")
			return
		}
		if err == users.ErrPasswordComplexity {
			WriteError(w, r, http.StatusUnprocessableEntity, "INVALID_PASSWORD", err.Error())
			return
		}
		WriteError(w, r, http.StatusConflict, "PASSWORD_CHANGE_CONFLICT", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleExportMe(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	profile, _, err := s.usersService.GetProfile(r.Context(), session.UserID)
	if err != nil {
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "Profile not found")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(profile)
}

func (s *Server) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	usage, err := s.usersService.GetQuota(r.Context(), session.UserID)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to calculate quota")
		return
	}

	resp := QuotaResponse{
		LogicalUsedBytes:   usage.LogicalUsedBytes,
		LogicalLimitBytes:  users.LogicalQuotaBytes,
		PhysicalUsedBytes:  usage.PhysicalUsedBytes,
		PhysicalLimitBytes: users.PhysicalQuotaBytes,
		FileCount:          usage.FileCount,
		FileCountLimit:     users.FileCountLimit,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

