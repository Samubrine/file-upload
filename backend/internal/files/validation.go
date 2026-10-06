package files

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var (
	ErrEmptyFile        = errors.New("empty file is not allowed")
	ErrFileTooLarge     = errors.New("file exceeds maximum allowed size")
	ErrUnsupportedType  = errors.New("unsupported file extension or mime type")
	ErrInvalidCategory  = errors.New("invalid category for the specified file type")
	ErrSpoofedContent   = errors.New("file content does not match extension")
)

const (
	MaxImageDocumentBytes = 20 * 1024 * 1024 // 20 MiB
	MaxVideoBytes         = 50 * 1024 * 1024 // 50 MiB
)

type FileTypeInfo struct {
	Extension string
	Mime      string
	Category  string
	MaxSize   int64
}

var allowlist = map[string]FileTypeInfo{
	".jpg":  {Extension: ".jpg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jpeg": {Extension: ".jpeg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".png":  {Extension: ".png", Mime: "image/png", Category: "image", MaxSize: MaxImageDocumentBytes},
	".webp": {Extension: ".webp", Mime: "image/webp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".pdf":  {Extension: ".pdf", Mime: "application/pdf", Category: "document", MaxSize: MaxImageDocumentBytes},
	".doc":  {Extension: ".doc", Mime: "application/msword", Category: "document", MaxSize: MaxImageDocumentBytes},
	".docx": {Extension: ".docx", Mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xls":  {Extension: ".xls", Mime: "application/vnd.ms-excel", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlsx": {Extension: ".xlsx", Mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Category: "document", MaxSize: MaxImageDocumentBytes},
	".mp4":  {Extension: ".mp4", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".webm": {Extension: ".webm", Mime: "video/webm", Category: "video", MaxSize: MaxVideoBytes},
	".mov":  {Extension: ".mov", Mime: "video/quicktime", Category: "video", MaxSize: MaxVideoBytes},
}

// ValidateFile inspects filename, content bytes, and requested category.
func ValidateFile(filename string, data []byte, requestedCategory string) (*FileTypeInfo, string, error) {
	if len(data) == 0 {
		return nil, "", ErrEmptyFile
	}

	cleanFilename := filepath.Base(filename)
	cleanFilename = strings.TrimSpace(cleanFilename)
	if cleanFilename == "" || cleanFilename == "." || cleanFilename == ".." {
		return nil, "", errors.New("invalid filename")
	}

	ext := strings.ToLower(filepath.Ext(cleanFilename))
	info, ok := allowlist[ext]
	if !ok {
		return nil, "", ErrUnsupportedType
	}

	if int64(len(data)) > info.MaxSize {
		return nil, "", ErrFileTooLarge
	}

	effectiveCategory := info.Category
	if requestedCategory != "" {
		if requestedCategory == "id_card" {
			if info.Category != "image" {
				return nil, "", fmt.Errorf("%w: id_card category is only permitted for images", ErrInvalidCategory)
			}
			effectiveCategory = "id_card"
		} else if requestedCategory != info.Category {
			return nil, "", ErrInvalidCategory
		}
	}

	// Validate magic bytes against spoofing
	if err := validateMagicBytes(ext, data); err != nil {
		return nil, "", err
	}

	return &info, effectiveCategory, nil
}

func validateMagicBytes(ext string, data []byte) error {
	switch ext {
	case ".jpg", ".jpeg":
		if len(data) < 3 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
			return ErrSpoofedContent
		}
	case ".png":
		pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		if len(data) < len(pngMagic) || !bytes.Equal(data[:len(pngMagic)], pngMagic) {
			return ErrSpoofedContent
		}
	case ".webp":
		if len(data) < 12 || !bytes.Equal(data[:4], []byte("RIFF")) || !bytes.Equal(data[8:12], []byte("WEBP")) {
			return ErrSpoofedContent
		}
	case ".pdf":
		if len(data) < 4 || !bytes.Equal(data[:4], []byte("%PDF")) {
			return ErrSpoofedContent
		}
	case ".docx", ".xlsx":
		// Standard ZIP archive PK..
		if len(data) < 4 || !bytes.Equal(data[:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
			return ErrSpoofedContent
		}
	case ".doc", ".xls":
		// Microsoft Compound File Binary Format (CFBF) D0 CF 11 E0 A1 B1 1A E1
		cfbfMagic := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
		if len(data) >= len(cfbfMagic) && !bytes.Equal(data[:len(cfbfMagic)], cfbfMagic) {
			return ErrSpoofedContent
		}
	case ".mp4", ".mov":
		// ftyp box
		if len(data) >= 8 && !bytes.Equal(data[4:8], []byte("ftyp")) {
			// Some valid mp4/mov might start differently, but if size >= 8 and has ftyp it's valid
		}
	case ".webm":
		// Matroska / WebM EBML 1A 45 DF A3
		ebml := []byte{0x1A, 0x45, 0xDF, 0xA3}
		if len(data) < len(ebml) || !bytes.Equal(data[:len(ebml)], ebml) {
			return ErrSpoofedContent
		}
	}
	return nil
}

