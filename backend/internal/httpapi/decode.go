package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// maxJSONBody bounds every JSON request body. The largest legitimate body is
// the registration or profile form, which is well under 1 KiB.
const maxJSONBody = 64 << 10

// decodeJSON reads exactly one JSON object into v. It refuses bodies larger
// than maxJSONBody (413), unknown fields and trailing data (400). On failure it
// writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			WriteError(w, r, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "Request body exceeds 64 KiB")
			return false
		}
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		WriteError(w, r, http.StatusBadRequest, "MALFORMED_INPUT", "Invalid JSON body")
		return false
	}
	return true
}
