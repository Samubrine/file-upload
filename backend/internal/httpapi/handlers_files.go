package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"ciphervault/internal/files"
)

type RenameInput struct {
	Filename string `json:"filename"`
}

type ListingInput struct {
	Listed bool `json:"listed"`
}

type MetadataPageResponse struct {
	Items  []files.MetadataDTO `json:"items"`
	Offset int                 `json:"offset"`
	Limit  int                 `json:"limit"`
	Total  int                 `json:"total"`
}

type OwnerPageResponse struct {
	Items  []files.OwnerFileDTO `json:"items"`
	Offset int                  `json:"offset"`
	Limit  int                  `json:"limit"`
	Total  int                  `json:"total"`
}

type SharedPageResponse struct {
	Items  []interface{} `json:"items"`
	Offset int           `json:"offset"`
	Limit  int           `json:"limit"`
	Total  int           `json:"total"`
}

func parsePagination(r *http.Request) (int, int) {
	offset := 0
	limit := 20

	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l >= 1 {
			if l > 100 {
				limit = 100
			} else {
				limit = l
			}
		}
	}
	return offset, limit
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)

	// Bounded reading in memory: max 55 MiB (video max 50 MiB + multipart overhead)
	if err := r.ParseMultipartForm(55 * 1024 * 1024); err != nil {
		WriteError(w, r, http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE", "Upload body too large")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "MISSING_FILE", "Missing 'file' field in multipart form")
		return
	}
	defer file.Close()

	category := r.FormValue("category")
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "READ_ERROR", "Failed to read uploaded file")
		return
	}

	dto, err := s.filesService.Upload(r.Context(), session.UserID, header.Filename, fileBytes, category)
	if err != nil {
		switch err {
		case files.ErrEmptyFile:
			WriteError(w, r, http.StatusBadRequest, "EMPTY_FILE", err.Error())
		case files.ErrFileTooLarge:
			WriteError(w, r, http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE", err.Error())
		case files.ErrUnsupportedType, files.ErrSpoofedContent:
			WriteError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_TYPE", err.Error())
		case files.ErrInvalidCategory:
			WriteError(w, r, http.StatusUnprocessableEntity, "INVALID_CATEGORY", err.Error())
		case files.ErrQuotaExceeded:
			WriteError(w, r, http.StatusConflict, "QUOTA_EXCEEDED", err.Error())
		default:
			WriteError(w, r, http.StatusInternalServerError, "UPLOAD_ERROR", err.Error())
		}
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(dto.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(dto)
}

func (s *Server) handleListMine(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	offset, limit := parsePagination(r)

	items, total, err := s.filesService.ListMine(r.Context(), session.UserID, offset, limit)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if items == nil {
		items = []files.OwnerFileDTO{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(OwnerPageResponse{
		Items:  items,
		Offset: offset,
		Limit:  limit,
		Total:  total,
	})
}

func (s *Server) handleListShared(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	offset, limit := parsePagination(r)

	items, total, err := s.filesService.ListShared(r.Context(), session.UserID, offset, limit)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if items == nil {
		items = []interface{}{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(SharedPageResponse{
		Items:  items,
		Offset: offset,
		Limit:  limit,
		Total:  total,
	})
}

func (s *Server) handleListListed(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)

	items, total, err := s.filesService.ListListed(r.Context(), offset, limit)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if items == nil {
		items = []files.MetadataDTO{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(MetadataPageResponse{
		Items:  items,
		Offset: offset,
		Limit:  limit,
		Total:  total,
	})
}

func (s *Server) handleGetFile(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	detail, rev, err := s.filesService.GetFileDetail(r.Context(), session.UserID, fileID)
	if err != nil {
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found or access denied")
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(rev, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(detail)
}

func (s *Server) handleRenameFile(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input RenameInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	dto, err := s.filesService.Rename(r.Context(), session.UserID, fileID, input.Filename, expectedRev)
	if err != nil {
		switch err {
		case files.ErrFileNotFound:
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		case files.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can rename file")
		case files.ErrExtensionChange:
			WriteError(w, r, http.StatusUnprocessableEntity, "EXTENSION_CHANGE", err.Error())
		default:
			WriteError(w, r, http.StatusConflict, "RENAME_CONFLICT", err.Error())
		}
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(dto.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dto)
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	if err := s.filesService.Delete(r.Context(), session.UserID, fileID, expectedRev); err != nil {
		switch err {
		case files.ErrFileNotFound:
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		case files.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can delete file")
		default:
			WriteError(w, r, http.StatusConflict, "DELETE_CONFLICT", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReplaceContent(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	if err := r.ParseMultipartForm(55 * 1024 * 1024); err != nil {
		WriteError(w, r, http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE", "Upload body too large")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "MISSING_FILE", "Missing 'file' field in multipart form")
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		WriteError(w, r, http.StatusInternalServerError, "READ_ERROR", "Failed to read replacement file")
		return
	}

	dto, err := s.filesService.Replace(r.Context(), session.UserID, fileID, fileBytes, expectedRev)
	if err != nil {
		switch err {
		case files.ErrFileNotFound:
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		case files.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can replace content")
		case files.ErrEmptyFile:
			WriteError(w, r, http.StatusBadRequest, "EMPTY_FILE", err.Error())
		case files.ErrFileTooLarge:
			WriteError(w, r, http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE", err.Error())
		case files.ErrUnsupportedType, files.ErrSpoofedContent:
			WriteError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_TYPE", err.Error())
		case files.ErrQuotaExceeded:
			WriteError(w, r, http.StatusConflict, "QUOTA_EXCEEDED", err.Error())
		default:
			WriteError(w, r, http.StatusConflict, "REPLACE_CONFLICT", err.Error())
		}
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(dto.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dto)
}

func (s *Server) handleSetListing(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")

	expectedRev, err := ParseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, "INVALID_IF_MATCH", err.Error())
		return
	}

	var input ListingInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return
	}

	dto, err := s.filesService.SetListing(r.Context(), session.UserID, fileID, input.Listed, expectedRev)
	if err != nil {
		switch err {
		case files.ErrFileNotFound:
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		case files.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Only owner can modify listing")
		default:
			WriteError(w, r, http.StatusConflict, "LISTING_CONFLICT", err.Error())
		}
		return
	}

	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(dto.Revision, 10)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dto)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	session := GetSession(r)
	fileID := r.PathValue("file_id")
	variantID := r.URL.Query().Get("variant")

	plaintext, meta, timings, err := s.filesService.Download(r.Context(), session.UserID, fileID, variantID)
	if err != nil {
		switch err {
		case files.ErrFileNotFound:
			WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "File not found")
		case files.ErrForbidden:
			WriteError(w, r, http.StatusForbidden, "FORBIDDEN", "Download permission denied")
		default:
			WriteError(w, r, http.StatusInternalServerError, "DOWNLOAD_ERROR", err.Error())
		}
		return
	}

	// Server-Timing header if benchmark mode enabled
	if s.benchmarkMode && timings != nil {
		serverTiming := fmt.Sprintf("db;dur=%.3f, kdf;dur=%.3f, mac;dur=%.3f, decrypt;dur=%.3f, total;dur=%.3f",
			float64(timings.DBReadDuration.Microseconds())/1000.0,
			float64(timings.KDFDuration.Microseconds())/1000.0,
			float64(timings.MACVerifyDuration.Microseconds())/1000.0,
			float64(timings.DecryptCipherDuration.Microseconds())/1000.0,
			float64(timings.OpenTotalDuration.Microseconds())/1000.0,
		)
		w.Header().Set("Server-Timing", serverTiming)
	}

	// Attachment disposition
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", meta.Filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plaintext)
}

