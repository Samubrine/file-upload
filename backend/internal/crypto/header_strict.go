package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// parseStrictHeader decodes the envelope header with three extra checks that
// encoding/json does not make by itself: duplicate keys are refused (json keeps
// the last one silently), unknown fields are refused, and nothing may follow the
// object. Any failure is reported as the generic integrity error.
func parseStrictHeader(raw []byte, h *Header) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrIntegrityCheckFailed
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] {
			return ErrIntegrityCheckFailed
		}
		seen[key] = true
		val, err := dec.Token()
		if err != nil {
			return ErrIntegrityCheckFailed
		}
		if _, nested := val.(json.Delim); nested {
			return ErrIntegrityCheckFailed
		}
	}

	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(h); err != nil {
		return ErrIntegrityCheckFailed
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrIntegrityCheckFailed
	}
	return nil
}
