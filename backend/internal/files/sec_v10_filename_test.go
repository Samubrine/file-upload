package files

import (
	"strings"
	"testing"
)

// V10: filenames may not contain control characters, may not start with a dot,
// and are limited to 180 runes.
func TestV10FilenameRules(t *testing.T) {
	bad := []string{
		"a\x00.pdf",
		"report\r\nSet-Cookie: x.pdf",
		"tab\there.pdf",
		".hidden.pdf",
		strings.Repeat("n", 200) + ".pdf",
	}
	for _, name := range bad {
		if _, _, err := ValidateFile(name, []byte("%PDF-1.4 x"), ""); err == nil {
			t.Errorf("filename %q accepted", name)
		}
	}
	if _, _, err := ValidateFile("ok name-1.pdf", []byte("%PDF-1.4 x"), ""); err != nil {
		t.Errorf("ordinary filename rejected: %v", err)
	}
}
