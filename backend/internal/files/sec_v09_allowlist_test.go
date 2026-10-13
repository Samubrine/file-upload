package files

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// V9: the allowlist is the 12 specified extensions plus 8 verifiable aliases.
// Every other type is refused, and each accepted type must carry its signature.
func TestV9RefusedTypes(t *testing.T) {
	cases := map[string][]byte{
		"logo.svg":     []byte("<svg xmlns='http://www.w3.org/2000/svg'></svg>"),
		"bundle.zip":   []byte("PK\x03\x04 archive"),
		"macro.docm":   []byte("PK\x03\x04 macro doc"),
		"sheet.xlsm":   []byte("PK\x03\x04 macro sheet"),
		"notes.txt":    []byte("plain text"),
		"data.csv":     []byte("a,b\n1,2\n"),
		"deck.pptx":    []byte("PK\x03\x04 slides"),
		"page.html":    []byte("<html></html>"),
		"tool.exe":     []byte("MZ\x90\x00"),
		"fake.mp4":     []byte("this is not an mp4 container at all"),
		"tiny.doc":     []byte("\xD0\xCF"),
		"logo.heic":    []byte("\x00\x00\x00\x18ftypheic"),
		"script.tar.gz": []byte("\x1f\x8b\x08"),
	}
	for name, data := range cases {
		if _, _, err := ValidateFile(name, data, ""); err == nil {
			t.Errorf("%s: expected refusal, got accepted", name)
		}
	}
}

func TestV9AcceptedAliasesRequireSignature(t *testing.T) {
	good := map[string][]byte{
		"a.jpe":  {0xFF, 0xD8, 0xFF, 0xE0},
		"a.jfif": {0xFF, 0xD8, 0xFF, 0xE0},
		"a.gif":  []byte("GIF89a...."),
		"a.bmp":  []byte("BM\x00\x00"),
		"a.tif":  []byte("II*\x00\x08\x00"),
		"a.tiff": []byte("MM\x00*\x00\x00"),
		"a.m4v":  append([]byte("\x00\x00\x00\x18"), []byte("ftypmp42")...),
		"a.mkv":  []byte("\x1A\x45\xDF\xA3\x9F"),
		"a.mov":  append([]byte("\x00\x00\x00\x14"), []byte("ftypqt  ")...),
		"a.doc":  []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1rest"),
	}
	for name, data := range good {
		if _, _, err := ValidateFile(name, data, ""); err != nil {
			t.Errorf("%s with valid signature rejected: %v", name, err)
		}
	}
}

func TestV9MagicBytesEnforced(t *testing.T) {
	bad := map[string][]byte{
		"a.mov":  append([]byte("\x00\x00\x00\x14"), []byte("abcdqt  ")...), // no ftyp
		"a.m4v":  []byte("\x00\x00\x00\x18moovmp42"),                            // moov, not ftyp
		"a.doc":  []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A"),                       // 7-byte prefix
		"a.xls":  []byte("\xD0\xCF\x11\xE0"),                                   // truncated signature
		"a.mkv":  []byte("\x1A\x45"),
	}
	for name, data := range bad {
		_, _, err := ValidateFile(name, data, "")
		if !errors.Is(err, ErrSpoofedContent) {
			t.Errorf("%s: expected ErrSpoofedContent, got %v", name, err)
		}
	}
}

func TestV9OriginalTwelveStillAccepted(t *testing.T) {
	ok := map[string][]byte{
		"a.jpg":  {0xFF, 0xD8, 0xFF},
		"a.jpeg": {0xFF, 0xD8, 0xFF},
		"a.png":  append([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, bytes.Repeat([]byte{0}, 4)...),
		"a.webp": []byte("RIFF\x00\x00\x00\x00WEBP"),
		"a.pdf":  []byte("%PDF-1.7"),
		"a.docx": []byte("PK\x03\x04x"),
		"a.xlsx": []byte("PK\x03\x04x"),
		"a.webm": []byte("\x1A\x45\xDF\xA3x"),
		"a.mp4":  append([]byte("\x00\x00\x00\x18"), []byte("ftypisom")...),
		"a.xls":  []byte("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1x"),
	}
	for name, data := range ok {
		if _, _, err := ValidateFile(name, data, ""); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	_ = strings.TrimSpace
}
