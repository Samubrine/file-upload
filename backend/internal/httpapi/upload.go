package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

// maxUploadBody bounds the whole multipart request: the largest allowed file
// (50 MiB video) plus 1 MiB for multipart framing and the category field.
const maxUploadBody = 51<<20 + 1<<20

const maxCategoryField = 64

type uploadError struct {
	status int
	code   string
	msg    string
}

// readSingleFile streams a multipart body that holds exactly one "file" part
// and an optional "category" text field. The body is capped at maxUploadBody
// before parsing, so the server never reads past the cap. Extra file parts and
// unknown fields are refused.
func readSingleFile(w http.ResponseWriter, r *http.Request) (filename string, data []byte, category string, ue *uploadError) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)
	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, "", &uploadError{http.StatusBadRequest, "MALFORMED_MULTIPART", "Expected a multipart/form-data body"}
	}

	seenFile := false
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, "", classifyUploadErr(err)
		}
		switch part.FormName() {
		case "file":
			if seenFile {
				return "", nil, "", &uploadError{http.StatusBadRequest, "MULTIPLE_FILES", "Upload exactly one file per request"}
			}
			seenFile = true
			if part.FileName() == "" {
				return "", nil, "", &uploadError{http.StatusBadRequest, "MISSING_FILE", "Missing 'file' field in multipart form"}
			}
			filename = part.FileName()
			data, err = io.ReadAll(part)
			if err != nil {
				return "", nil, "", classifyUploadErr(err)
			}
		case "category":
			b, err := io.ReadAll(io.LimitReader(part, maxCategoryField+1))
			if err != nil {
				return "", nil, "", classifyUploadErr(err)
			}
			if len(b) > maxCategoryField {
				return "", nil, "", &uploadError{http.StatusBadRequest, "MALFORMED_MULTIPART", "category field is too long"}
			}
			category = strings.TrimSpace(string(b))
		default:
			return "", nil, "", &uploadError{http.StatusBadRequest, "UNKNOWN_FIELD", "Unexpected form field"}
		}
	}
	if !seenFile {
		return "", nil, "", &uploadError{http.StatusBadRequest, "MISSING_FILE", "Missing 'file' field in multipart form"}
	}
	return filename, data, category, nil
}

func classifyUploadErr(err error) *uploadError {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return &uploadError{http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "Upload body exceeds the allowed size"}
	}
	return &uploadError{http.StatusBadRequest, "MALFORMED_MULTIPART", "Malformed multipart body"}
}
