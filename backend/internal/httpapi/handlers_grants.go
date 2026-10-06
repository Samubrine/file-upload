package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"
)

type GrantSetInput struct {
	ViewMetadata bool `json:"view_metadata"`
	Download     bool `json:"download"`
}

func (s *Server) handleGetGrants(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	grants, err := s.sharingService.GetGrants(r.Context(), session.UserID, fileID)
	if err != nil {
		if err == sharing.ErrForbidden {
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can view grants")
			return
		}
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		return
	}
	if grants == nil {
		grants = []sharing.GrantDTO{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(grants)
}

func (s *Server) handlePutGrant(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")
	username := r.PathValue("username")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input GrantSetInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	updatedFile, err := s.sharingService.PutGrant(r.Context(), session.UserID, fileID, username, input.ViewMetadata, input.Download, expectedRev)
	if err != nil {
		switch err {
		case sharing.ErrInvalidGrant, sharing.ErrSelfGrant:
			WriteError(w, r, http.StatusUnprocessableEntity, "INVALID_GRANT", err.Error())
		case sharing.ErrRecipientNotFound:
			WriteError(w, r, http.StatusNotFound, "RECIPIENT_NOT_FOUND", "Recipient username not found")
		case sharing.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can manage grants")
		case storage.ErrConflict:
			WriteError(w, r, http.StatusConflict, "CONFLICT", "File revision conflict")
		default:
			WriteError(w, r, http.StatusConflict, "GRANT_ERROR", err.Error())
		}
		return
	}

	// Fetch owner file DTO
	ownerDTO, _, err := s.filesService.GetFileDetail(r.Context(), session.UserID, fileID)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve updated file")
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(updatedFile.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(ownerDTO)
}

func (s *Server) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")
	username := r.PathValue("username")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	updatedFile, err := s.sharingService.DeleteGrant(r.Context(), session.UserID, fileID, username, expectedRev)
	if err != nil {
		switch err {
		case sharing.ErrRecipientNotFound:
			WriteError(w, r, http.StatusNotFound, "RECIPIENT_NOT_FOUND", "Recipient username not found")
		case sharing.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can manage grants")
		case storage.ErrConflict:
			WriteError(w, r, http.StatusConflict, "CONFLICT", "File revision conflict")
		default:
			WriteError(w, r, http.StatusConflict, "GRANT_ERROR", err.Error())
		}
		return
	}

	ownerDTO, _, err := s.filesService.GetFileDetail(r.Context(), session.UserID, fileID)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve updated file")
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(updatedFile.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(ownerDTO)
}

