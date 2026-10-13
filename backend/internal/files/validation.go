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

// Allowlist supporting multiple extensions for each filetype/category
var allowlist = map[string]FileTypeInfo{
	// Images (Category: "image", also permitted for "id_card")
	".jpg":   {Extension: ".jpg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jpeg":  {Extension: ".jpeg", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jpe":   {Extension: ".jpe", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jfif":  {Extension: ".jfif", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".jif":   {Extension: ".jif", Mime: "image/jpeg", Category: "image", MaxSize: MaxImageDocumentBytes},
	".png":   {Extension: ".png", Mime: "image/png", Category: "image", MaxSize: MaxImageDocumentBytes},
	".apng":  {Extension: ".apng", Mime: "image/apng", Category: "image", MaxSize: MaxImageDocumentBytes},
	".webp":  {Extension: ".webp", Mime: "image/webp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".gif":   {Extension: ".gif", Mime: "image/gif", Category: "image", MaxSize: MaxImageDocumentBytes},
	".bmp":   {Extension: ".bmp", Mime: "image/bmp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".dib":   {Extension: ".dib", Mime: "image/bmp", Category: "image", MaxSize: MaxImageDocumentBytes},
	".tiff":  {Extension: ".tiff", Mime: "image/tiff", Category: "image", MaxSize: MaxImageDocumentBytes},
	".tif":   {Extension: ".tif", Mime: "image/tiff", Category: "image", MaxSize: MaxImageDocumentBytes},
	".ico":   {Extension: ".ico", Mime: "image/x-icon", Category: "image", MaxSize: MaxImageDocumentBytes},
	".svg":   {Extension: ".svg", Mime: "image/svg+xml", Category: "image", MaxSize: MaxImageDocumentBytes},
	".heic":  {Extension: ".heic", Mime: "image/heic", Category: "image", MaxSize: MaxImageDocumentBytes},
	".heif":  {Extension: ".heif", Mime: "image/heif", Category: "image", MaxSize: MaxImageDocumentBytes},

	// Documents (Category: "document")
	".pdf":      {Extension: ".pdf", Mime: "application/pdf", Category: "document", MaxSize: MaxImageDocumentBytes},
	".doc":      {Extension: ".doc", Mime: "application/msword", Category: "document", MaxSize: MaxImageDocumentBytes},
	".dot":      {Extension: ".dot", Mime: "application/msword", Category: "document", MaxSize: MaxImageDocumentBytes},
	".docx":     {Extension: ".docx", Mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Category: "document", MaxSize: MaxImageDocumentBytes},
	".dotx":     {Extension: ".dotx", Mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.template", Category: "document", MaxSize: MaxImageDocumentBytes},
	".docm":     {Extension: ".docm", Mime: "application/vnd.ms-word.document.macroEnabled.12", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xls":      {Extension: ".xls", Mime: "application/vnd.ms-excel", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlt":      {Extension: ".xlt", Mime: "application/vnd.ms-excel", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlsx":     {Extension: ".xlsx", Mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xltx":     {Extension: ".xltx", Mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.template", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlsm":     {Extension: ".xlsm", Mime: "application/vnd.ms-excel.sheet.macroEnabled.12", Category: "document", MaxSize: MaxImageDocumentBytes},
	".xlsb":     {Extension: ".xlsb", Mime: "application/vnd.ms-excel.sheet.binary.macroEnabled.12", Category: "document", MaxSize: MaxImageDocumentBytes},
	".csv":      {Extension: ".csv", Mime: "text/csv", Category: "document", MaxSize: MaxImageDocumentBytes},
	".ppt":      {Extension: ".ppt", Mime: "application/vnd.ms-powerpoint", Category: "document", MaxSize: MaxImageDocumentBytes},
	".pps":      {Extension: ".pps", Mime: "application/vnd.ms-powerpoint", Category: "document", MaxSize: MaxImageDocumentBytes},
	".pot":      {Extension: ".pot", Mime: "application/vnd.ms-powerpoint", Category: "document", MaxSize: MaxImageDocumentBytes},
	".pptx":     {Extension: ".pptx", Mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", Category: "document", MaxSize: MaxImageDocumentBytes},
	".ppsx":     {Extension: ".ppsx", Mime: "application/vnd.openxmlformats-officedocument.presentationml.slideshow", Category: "document", MaxSize: MaxImageDocumentBytes},
	".potx":     {Extension: ".potx", Mime: "application/vnd.openxmlformats-officedocument.presentationml.template", Category: "document", MaxSize: MaxImageDocumentBytes},
	".odt":      {Extension: ".odt", Mime: "application/vnd.oasis.opendocument.text", Category: "document", MaxSize: MaxImageDocumentBytes},
	".ods":      {Extension: ".ods", Mime: "application/vnd.oasis.opendocument.spreadsheet", Category: "document", MaxSize: MaxImageDocumentBytes},
	".odp":      {Extension: ".odp", Mime: "application/vnd.oasis.opendocument.presentation", Category: "document", MaxSize: MaxImageDocumentBytes},
	".rtf":      {Extension: ".rtf", Mime: "application/rtf", Category: "document", MaxSize: MaxImageDocumentBytes},
	".txt":      {Extension: ".txt", Mime: "text/plain", Category: "document", MaxSize: MaxImageDocumentBytes},
	".text":     {Extension: ".text", Mime: "text/plain", Category: "document", MaxSize: MaxImageDocumentBytes},
	".md":       {Extension: ".md", Mime: "text/markdown", Category: "document", MaxSize: MaxImageDocumentBytes},
	".markdown": {Extension: ".markdown", Mime: "text/markdown", Category: "document", MaxSize: MaxImageDocumentBytes},
	".tar.gz":   {Extension: ".tar.gz", Mime: "application/gzip", Category: "document", MaxSize: MaxImageDocumentBytes},
	".tgz":      {Extension: ".tgz", Mime: "application/gzip", Category: "document", MaxSize: MaxImageDocumentBytes},
	".zip":      {Extension: ".zip", Mime: "application/zip", Category: "document", MaxSize: MaxImageDocumentBytes},

	// Video (Category: "video")
	".mp4":  {Extension: ".mp4", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".m4v":  {Extension: ".m4v", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".mp4v": {Extension: ".mp4v", Mime: "video/mp4", Category: "video", MaxSize: MaxVideoBytes},
	".webm": {Extension: ".webm", Mime: "video/webm", Category: "video", MaxSize: MaxVideoBytes},
	".mov":  {Extension: ".mov", Mime: "video/quicktime", Category: "video", MaxSize: MaxVideoBytes},
	".qt":   {Extension: ".qt", Mime: "video/quicktime", Category: "video", MaxSize: MaxVideoBytes},
	".mkv":  {Extension: ".mkv", Mime: "video/x-matroska", Category: "video", MaxSize: MaxVideoBytes},
	".avi":  {Extension: ".avi", Mime: "video/x-msvideo", Category: "video", MaxSize: MaxVideoBytes},
	".wmv":  {Extension: ".wmv", Mime: "video/x-ms-wmv", Category: "video", MaxSize: MaxVideoBytes},
	".flv":  {Extension: ".flv", Mime: "video/x-flv", Category: "video", MaxSize: MaxVideoBytes},
	".3gp":  {Extension: ".3gp", Mime: "video/3gpp", Category: "video", MaxSize: MaxVideoBytes},
	".3g2":  {Extension: ".3g2", Mime: "video/3gpp2", Category: "video", MaxSize: MaxVideoBytes},
	".ogv":  {Extension: ".ogv", Mime: "video/ogg", Category: "video", MaxSize: MaxVideoBytes},
	".ogg":  {Extension: ".ogg", Mime: "video/ogg", Category: "video", MaxSize: MaxVideoBytes},
	".mpg":  {Extension: ".mpg", Mime: "video/mpeg", Category: "video", MaxSize: MaxVideoBytes},
	".mpeg": {Extension: ".mpeg", Mime: "video/mpeg", Category: "video", MaxSize: MaxVideoBytes},
	".m2v":  {Extension: ".m2v", Mime: "video/mpeg", Category: "video", MaxSize: MaxVideoBytes},
	".ts":   {Extension: ".ts", Mime: "video/mp2t", Category: "video", MaxSize: MaxVideoBytes},
}

// ExtractExtension returns the lowercased extension, recognizing compound extensions like .tar.gz
func ExtractExtension(filename string) string {
	lower := strings.ToLower(filename)
	compoundExts := []string{".tar.gz", ".tar.bz2", ".tar.xz"}
	for _, ce := range compoundExts {
		if strings.HasSuffix(lower, ce) {
			return ce
		}
	}
	return strings.ToLower(filepath.Ext(filename))
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

	ext := ExtractExtension(cleanFilename)
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
	case ".jpg", ".jpeg", ".jpe", ".jfif", ".jif":
		if len(data) < 3 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
			return ErrSpoofedContent
		}
	case ".png", ".apng":
		pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		if len(data) < len(pngMagic) || !bytes.Equal(data[:len(pngMagic)], pngMagic) {
			return ErrSpoofedContent
		}
	case ".gif":
		if len(data) < 6 || (!bytes.Equal(data[:6], []byte("GIF87a")) && !bytes.Equal(data[:6], []byte("GIF89a"))) {
			return ErrSpoofedContent
		}
	case ".bmp", ".dib":
		if len(data) < 2 || data[0] != 0x42 || data[1] != 0x4D {
			return ErrSpoofedContent
		}
	case ".tiff", ".tif":
		if len(data) < 4 {
			return ErrSpoofedContent
		}
		isLE := data[0] == 0x49 && data[1] == 0x49 && data[2] == 0x2A && data[3] == 0x00
		isBE := data[0] == 0x4D && data[1] == 0x4D && data[2] == 0x00 && data[3] == 0x2A
		if !isLE && !isBE {
			return ErrSpoofedContent
		}
	case ".ico":
		if len(data) < 4 || data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x01 || data[3] != 0x00 {
			return ErrSpoofedContent
		}
	case ".svg":
		trimmed := bytes.TrimSpace(data)
		limit := len(trimmed)
		if limit > 512 {
			limit = 512
		}
		if len(trimmed) < 4 || (!bytes.HasPrefix(trimmed, []byte("<?xml")) && !bytes.HasPrefix(trimmed, []byte("<svg")) && !bytes.Contains(trimmed[:limit], []byte("<svg"))) {
			return ErrSpoofedContent
		}
	case ".heic", ".heif":
		if len(data) < 12 || !bytes.Equal(data[4:8], []byte("ftyp")) {
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
	case ".docx", ".dotx", ".docm", ".xlsx", ".xltx", ".xlsm", ".pptx", ".ppsx", ".potx", ".odt", ".ods", ".odp", ".zip":
		// Standard ZIP archive PK..
		if len(data) < 4 || !bytes.Equal(data[:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
			return ErrSpoofedContent
		}
	case ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pot":
		// Microsoft Compound File Binary Format (CFBF) D0 CF 11 E0 A1 B1 1A E1
		cfbfMagic := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
		if len(data) >= len(cfbfMagic) && !bytes.Equal(data[:len(cfbfMagic)], cfbfMagic) {
			return ErrSpoofedContent
		}
	case ".rtf":
		if len(data) < 5 || !bytes.Equal(data[:5], []byte("{\rtf")) {
			return ErrSpoofedContent
		}
	case ".tar.gz", ".tgz":
		// Gzip magic: 1F 8B
		if len(data) < 2 || data[0] != 0x1F || data[1] != 0x8B {
			return ErrSpoofedContent
		}
	case ".txt", ".text", ".csv", ".md", ".markdown":
		// Plaintext formats: check that first 512 bytes don't contain null bytes
		limit := len(data)
		if limit > 512 {
			limit = 512
		}
		if bytes.IndexByte(data[:limit], 0x00) != -1 {
			return ErrSpoofedContent
		}
	case ".mp4", ".m4v", ".mp4v", ".mov", ".qt", ".3gp", ".3g2":
		// QuickTime/MP4 container: usually has ftyp/moov/mdat/skip/wide in bytes 4..8
		if len(data) >= 8 {
			box := string(data[4:8])
			if box != "ftyp" && box != "moov" && box != "mdat" && box != "wide" && box != "skip" && box != "free" {
				// Permissive check for containers
			}
		}
	case ".webm", ".mkv":
		// Matroska / WebM EBML 1A 45 DF A3
		ebml := []byte{0x1A, 0x45, 0xDF, 0xA3}
		if len(data) < len(ebml) || !bytes.Equal(data[:len(ebml)], ebml) {
			return ErrSpoofedContent
		}
	case ".avi":
		if len(data) < 12 || !bytes.Equal(data[:4], []byte("RIFF")) || !bytes.Equal(data[8:12], []byte("AVI ")) {
			return ErrSpoofedContent
		}
	case ".wmv":
		asfMagic := []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}
		if len(data) < len(asfMagic) || !bytes.Equal(data[:len(asfMagic)], asfMagic) {
			return ErrSpoofedContent
		}
	case ".flv":
		if len(data) < 3 || !bytes.Equal(data[:3], []byte("FLV")) {
			return ErrSpoofedContent
		}
	case ".ogv", ".ogg":
		if len(data) < 4 || !bytes.Equal(data[:4], []byte("OggS")) {
			return ErrSpoofedContent
		}
	}
	return nil
}

