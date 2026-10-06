package files

import (
	"bytes"
	"testing"
)

func TestValidationRules(t *testing.T) {
	// 1. Empty file rejected
	_, _, err := ValidateFile("test.png", []byte(""), "image")
	if err != ErrEmptyFile {
		t.Errorf("expected ErrEmptyFile, got %v", err)
	}

	// 2. Unsupported extension rejected
	_, _, err = ValidateFile("script.exe", []byte("MZ..."), "")
	if err != ErrUnsupportedType {
		t.Errorf("expected ErrUnsupportedType, got %v", err)
	}

	// 3. Spoofed content rejected
	_, _, err = ValidateFile("fake.png", []byte("not a png file"), "image")
	if err != ErrSpoofedContent {
		t.Errorf("expected ErrSpoofedContent, got %v", err)
	}

	// 4. ID card category rejected on non-image
	pdfMagic := []byte("%PDF-1.4 sample pdf")
	_, _, err = ValidateFile("doc.pdf", pdfMagic, "id_card")
	if err == nil {
		t.Errorf("expected error when setting id_card on PDF document")
	}

	// 5. Valid PNG with id_card category accepted
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00}
	info, cat, err := ValidateFile("my_id.png", pngHeader, "id_card")
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cat != "id_card" || info.Category != "image" {
		t.Errorf("unexpected category resolution: cat=%s info.Cat=%s", cat, info.Category)
	}

	// 6. Oversized image rejected (> 20 MiB)
	largeData := bytes.Repeat([]byte("A"), 21*1024*1024)
	_, _, err = ValidateFile("huge.jpg", largeData, "image")
	if err != ErrFileTooLarge {
		t.Errorf("expected ErrFileTooLarge, got %v", err)
	}
}

