package files

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrEmptyFile       = errors.New("empty file is not allowed")
	ErrFileTooLarge    = errors.New("file exceeds maximum allowed size")
	ErrUnsupportedType = errors.New("unsupported file extension or mime type")
	ErrInvalidCategory = errors.New("invalid category for the specified file type")
	ErrSpoofedContent  = errors.New("file content does not match extension")
	ErrInvalidFilename = errors.New("filename is not allowed")
)

const (
	MaxImageDocumentBytes = 20 * 1024 * 1024 // 20 MiB
	MaxVideoBytes         = 50 * 1024 * 1024 // 50 MiB
	maxFilenameRunes      = 180
)

type FileTypeInfo struct {
	Extension string
	Mime      string
	Category  string
	MaxSize   int64
}

// allowlist is the 12 extensions in docs/01-product.md plus 8 aliases whose
// signatures can be checked. Nothing else is accepted.
var allowlist = map[string]FileTypeInfo{
	".jpg":  {Extension: ".jpg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jpeg": {Extension: ".jpeg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jpe":  {Extension: ".jpe", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jfif": {Extension: ".jfif", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".png":  {Extension: ".png", Mime: "image/png", Category: "image", MaxSize: MaxImageDocumentBytes},
	".webp": {Extension: ".webp", Mime: "image/webp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".gif":  {Extension: ".gif", Mime: "image/gif", Category: "image", MaxSize: MaxImageDocumentBytes},
	".bmp":  {Extension: ".bmp", Mime: "image/bmp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".tif":  {Extension: ".tif", Mime: "image/tiff", Category: "image", MaxSize: MaxImageDocumentBytes},
	".tiff": {Extension: ".tiff", Mime: "image/tiff", Category: "image", MaxSize: MaxImageDocumentBytes},

	".pdf":  {Extension: ".pdf", Mime: "application/pdf", Category: "document", MaxSize: MaxImageDocumentBytes},
	".doc":  {Extension: ".doc", Mime: "application/msword", Category: "document", MaxSize: MaxImageDocumentBytes},
	".docx": {Extension: ".docx", Mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xls":  {Extension: ".xls", Mime: "application/vnd.ms-excel", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlsx": {Extension: ".xlsx", Mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Category: "document", MaxSize: MaxImageDocumentBytes},

	".mp4":  {Extension: ".mp4", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".m4v":  {Extension: ".m4v", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".webm": {Extension: ".webm", Mime: "video/webm", Category: "video", MaxSize: MaxVideoBytes},
	".mkv":  {Extension: ".mkv", Mime: "video/x-matroska", Category: "video", MaxSize: MaxVideoBytes},
	".mov":  {Extension: ".mov", Mime: "video/quicktime", Category: "video", MaxSize: MaxVideoBytes},
}

// validateFilename returns the base name if it is safe to store and display.
// Control characters (including NUL, CR, LF, tab), leading dots, empty names and
// names longer than 180 runes are refused. Path separators are stripped.
func validateFilename(name string) (string, error) {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == ".." || strings.HasPrefix(base, ".") {
		return "", ErrInvalidFilename
	}
	if !utf8.ValidString(base) || utf8.RuneCountInString(base) > maxFilenameRunes {
		return "", ErrInvalidFilename
	}
	for _, r := range base {
		if unicode.IsControl(r) {
			return "", ErrInvalidFilename
		}
	}
	return base, nil
}

// ValidateFile checks name, size, requested category and content signature.
func ValidateFile(filename string, data []byte, requestedCategory string) (*FileTypeInfo, string, error) {
	if len(data) == 0 {
		return nil, "", ErrEmptyFile
	}
	clean, err := validateFilename(filename)
	if err != nil {
		return nil, "", err
	}

	ext := strings.ToLower(filepath.Ext(clean))
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

	if err := validateMagicBytes(ext, data); err != nil {
		return nil, "", err
	}
	return &info, effectiveCategory, nil
}

func validateMagicBytes(ext string, data []byte) error {
	ok := false
	switch ext {
	case ".jpg", ".jpeg", ".jpe", ".jfif":
		ok = len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF
	case ".png":
		ok = bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	case ".webp":
		ok = len(data) >= 12 && bytes.HasPrefix(data, []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP"))
	case ".gif":
		ok = bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))
	case ".bmp":
		ok = bytes.HasPrefix(data, []byte("BM"))
	case ".tif", ".tiff":
		ok = bytes.HasPrefix(data, []byte{0x49, 0x49, 0x2A, 0x00}) || bytes.HasPrefix(data, []byte{0x4D, 0x4D, 0x00, 0x2A})
	case ".pdf":
		ok = bytes.HasPrefix(data, []byte("%PDF"))
	case ".docx", ".xlsx":
		ok = bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04})
	case ".doc", ".xls":
		ok = bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	case ".mp4", ".m4v", ".mov":
		ok = len(data) >= 8 && bytes.Equal(data[4:8], []byte("ftyp"))
	case ".webm", ".mkv":
		ok = bytes.HasPrefix(data, []byte{0x1A, 0x45, 0xDF, 0xA3})
	default:
		ok = false
	}
	if !ok {
		return ErrSpoofedContent
	}
	return nil
}
