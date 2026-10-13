package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"ciphervault/internal/apperr"
	"ciphervault/internal/storage"
)

type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	reqID := GetRequestID(r)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Code:      code,
		Message:   message,
		RequestID: reqID,
	})
}

// writeServiceError maps a service error to a response. Validation messages are
// returned as-is. Storage conflicts get a fixed message. Anything else is logged
// with the request ID and answered with a generic 500, so database or crypto
// details never reach the client.
func writeServiceError(w http.ResponseWriter, r *http.Request, err error, conflictCode string) {
	switch {
	case apperr.IsValidation(err):
		WriteError(w, r, http.StatusUnprocessableEntity, "INVALID_INPUT", err.Error())
	case errors.Is(err, storage.ErrConflict):
		WriteError(w, r, http.StatusConflict, conflictCode, "The item changed or conflicts with existing data. Reload and try again.")
	default:
		log.Printf("request %s: internal error: %q", GetRequestID(r), err.Error())
		WriteError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Something went wrong. Please try again.")
	}
}
