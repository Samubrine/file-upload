package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ciphervault/internal/crypto"
	"ciphervault/internal/sharing"
	"ciphervault/internal/storage"

	"github.com/google/uuid"
)

var (
	ErrQuotaExceeded   = errors.New("storage quota exceeded")
	ErrFileNotFound    = errors.New("file not found")
	ErrForbidden       = errors.New("permission denied")
	ErrExtensionChange = errors.New("cannot change file extension during rename")
)

type FileMetadata struct {
	Filename  string `json:"filename"`
	Extension string `json:"extension"`
	Mime      string `json:"mime"`
	Category  string `json:"category"`
}

type MetadataDTO struct {
	ID            string `json:"id"`
	Filename      string `json:"filename"`
	OwnerUsername string `json:"owner_username"`
}

type DownloadFileDTO struct {
	ID              string   `json:"id"`
	Filename        string   `json:"filename"`
	OwnerUsername   string   `json:"owner_username"`
	Revision        int64    `json:"revision"`
	ContentRevision int64    `json:"content_revision"`
	SizeBytes       int64    `json:"size_bytes"`
	Mime            string   `json:"mime"`
	Variants        []string `json:"variants"`
}

type OwnerFileDTO struct {
	ID              string   `json:"id"`
	Filename        string   `json:"filename"`
	OwnerUsername   string   `json:"owner_username"`
	Revision        int64    `json:"revision"`
	ContentRevision int64    `json:"content_revision"`
	SizeBytes       int64    `json:"size_bytes"`
	Mime            string   `json:"mime"`
	Variants        []string `json:"variants"`
	Listed          bool     `json:"listed"`
}

type DownloadTimings struct {
	DBReadDuration        time.Duration
	KDFDuration           time.Duration
	MACVerifyDuration     time.Duration
	DecryptCipherDuration time.Duration
	OpenTotalDuration     time.Duration
}

type Service struct {
	db              *storage.DB
	keyProvider     crypto.KeyProvider
	activeRootKeyID string
}

func NewService(db *storage.DB, kp crypto.KeyProvider, activeRootKeyID string) *Service {
	return &Service{
		db:              db,
		keyProvider:     kp,
		activeRootKeyID: activeRootKeyID,
	}
}

func (s *Service) sealVariants(ctx crypto.Context, plaintext []byte) ([]storage.PayloadVariantRow, int64, error) {
	rootKey, err := s.keyProvider.GetRootKey(s.activeRootKeyID)
	if err != nil {
		return nil, 0, fmt.Errorf("active root key error: %w", err)
	}

	variants := make([]storage.PayloadVariantRow, 0, len(crypto.AllVariantIDs))
	var totalEnvelopeBytes int64

	for _, vID := range crypto.AllVariantIDs {
		vCtx := ctx
		vCtx.VariantID = vID

		env, _, err := crypto.Seal(vCtx, s.activeRootKeyID, rootKey, plaintext)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to seal variant %s: %w", vID, err)
		}

		envLen := int64(len(env))
		totalEnvelopeBytes += envLen
		variants = append(variants, storage.PayloadVariantRow{
			PayloadID:     ctx.PayloadID,
			VariantID:     vID,
			Envelope:      env,
			EnvelopeBytes: envLen,
		})
	}

	return variants, totalEnvelopeBytes, nil
}

func (s *Service) getOwnerUsername(tx *sql.Tx, ownerID string) (string, error) {
	u, err := s.db.GetUserByID(tx, ownerID)
	if err != nil {
		return "", err
	}
	variantRow, err := s.db.GetPayloadVariant(tx, u.ProfilePayloadID, crypto.DefaultVariant)
	if err != nil {
		return "", err
	}
	ctx := crypto.Context{
		PayloadID:       u.ProfilePayloadID,
		OwnerID:         ownerID,
		FileID:          nil,
		ContentRevision: 1,
		VariantID:       crypto.DefaultVariant,
	}
	pt, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
	if err != nil {
		return "", err
	}
	var p struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(pt, &p); err != nil {
		return "", err
	}
	return p.Username, nil
}

func (s *Service) getFileMetadata(tx *sql.Tx, f *storage.FileRow) (*FileMetadata, error) {
	variantRow, err := s.db.GetPayloadVariant(tx, f.MetadataPayloadID, crypto.DefaultVariant)
	if err != nil {
		return nil, err
	}
	ctx := crypto.Context{
		PayloadID:       f.MetadataPayloadID,
		OwnerID:         f.OwnerID,
		FileID:          &f.ID,
		ContentRevision: f.ContentRevision,
		VariantID:       crypto.DefaultVariant,
	}
	pt, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
	if err != nil {
		return nil, err
	}
	var meta FileMetadata
	if err := json.Unmarshal(pt, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// Upload validates, seals 14 content variants + 14 metadata variants, and persists the file atomically.
func (s *Service) Upload(c context.Context, ownerID, filename string, content []byte, category string) (*OwnerFileDTO, error) {
	typeInfo, effCategory, err := ValidateFile(filename, content, category)
	if err != nil {
		return nil, err
	}

	cleanFilename := filepath.Base(filename)
	meta := FileMetadata{
		Filename:  cleanFilename,
		Extension: typeInfo.Extension,
		Mime:      typeInfo.Mime,
		Category:  effCategory,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}

	fileID := uuid.New().String()
	contentPayloadID := uuid.New().String()
	metadataPayloadID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	cCtx := crypto.Context{
		PayloadID:       contentPayloadID,
		OwnerID:         ownerID,
		FileID:          &fileID,
		ContentRevision: 1,
	}
	contentVariants, contentPhysicalBytes, err := s.sealVariants(cCtx, content)
	if err != nil {
		return nil, err
	}

	mCtx := crypto.Context{
		PayloadID:       metadataPayloadID,
		OwnerID:         ownerID,
		FileID:          &fileID,
		ContentRevision: 1,
	}
	metadataVariants, metadataPhysicalBytes, err := s.sealVariants(mCtx, metaBytes)
	if err != nil {
		return nil, err
	}

	logicalBytes := int64(len(content))
	physicalBytes := contentPhysicalBytes + metadataPhysicalBytes

	var ownerUsername string
	err = s.db.WithTx(c, func(tx *sql.Tx) error {
		// Quota check
		usage, err := s.db.GetUserQuotas(tx, ownerID)
		if err != nil {
			return err
		}
		if usage.FileCount >= 100 {
			return ErrQuotaExceeded
		}
		if usage.LogicalUsedBytes+logicalBytes > 100*1024*1024 {
			return ErrQuotaExceeded
		}
		if usage.PhysicalUsedBytes+physicalBytes > 2*1024*1024*1024 {
			return ErrQuotaExceeded
		}

		// Create content payload & variants
		cRow := storage.PayloadRow{
			ID:              contentPayloadID,
			Kind:            "file_content",
			ContextOwnerID:  ownerID,
			ContextFileID:   &fileID,
			ContentRevision: 1,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, cRow, contentVariants); err != nil {
			return err
		}

		// Create metadata payload & variants
		mRow := storage.PayloadRow{
			ID:              metadataPayloadID,
			Kind:            "file_metadata",
			ContextOwnerID:  ownerID,
			ContextFileID:   &fileID,
			ContentRevision: 1,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, mRow, metadataVariants); err != nil {
			return err
		}

		// Create file record
		fRow := storage.FileRow{
			ID:                fileID,
			OwnerID:           ownerID,
			ContentPayloadID:  contentPayloadID,
			MetadataPayloadID: metadataPayloadID,
			ContentRevision:   1,
			Revision:          1,
			Listed:            false,
			LogicalBytes:      logicalBytes,
			PhysicalBytes:     physicalBytes,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		if err := s.db.CreateFile(tx, fRow); err != nil {
			return err
		}

		username, err := s.getOwnerUsername(tx, ownerID)
		if err != nil {
			return err
		}
		ownerUsername = username
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &OwnerFileDTO{
		ID:              fileID,
		Filename:        cleanFilename,
		OwnerUsername:   ownerUsername,
		Revision:        1,
		ContentRevision: 1,
		SizeBytes:       logicalBytes,
		Mime:            typeInfo.Mime,
		Variants:        crypto.AllVariantIDs,
		Listed:          false,
	}, nil
}

// Download verifies caller permissions, loads envelope, authenticates, and decrypts.
func (s *Service) Download(c context.Context, callerID, fileID, variantID string) ([]byte, *FileMetadata, *DownloadTimings, error) {
	if variantID == "" {
		variantID = crypto.DefaultVariant
	}
	if !crypto.IsValidVariant(variantID) {
		return nil, nil, nil, errors.New("unsupported variant id")
	}

	timings := &DownloadTimings{}
	var plaintext []byte
	var meta *FileMetadata

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}

		grant, _ := s.db.GetGrant(tx, fileID, callerID)
		perm := sharing.EvaluatePermissions(callerID, f, grant)
		if !perm.CanViewMetadata {
			return ErrFileNotFound // Hidden from unauthorized users
		}
		if !perm.CanDownload {
			return ErrForbidden // Metadata is visible, but download is forbidden
		}

		m, err := s.getFileMetadata(tx, f)
		if err != nil {
			return err
		}
		meta = m

		dbStart := time.Now()
		vRow, err := s.db.GetPayloadVariant(tx, f.ContentPayloadID, variantID)
		if err != nil {
			return err
		}
		timings.DBReadDuration = time.Since(dbStart)

		ctx := crypto.Context{
			PayloadID:       f.ContentPayloadID,
			OwnerID:         f.OwnerID,
			FileID:          &f.ID,
			ContentRevision: f.ContentRevision,
			VariantID:       variantID,
		}

		pt, openTimings, err := crypto.Open(ctx, s.keyProvider, vRow.Envelope)
		if err != nil {
			return err
		}

		timings.KDFDuration = openTimings.KDFDuration
		timings.MACVerifyDuration = openTimings.MACVerifyDuration
		timings.DecryptCipherDuration = openTimings.DecryptCipherDuration
		timings.OpenTotalDuration = openTimings.OpenTotalDuration

		plaintext = pt
		return nil
	})

	if err != nil {
		return nil, nil, nil, err
	}
	return plaintext, meta, timings, nil
}

// Rename updates display filename while preserving extension and content.
func (s *Service) Rename(c context.Context, ownerID, fileID, newFilename string, expectedRev int64) (*OwnerFileDTO, error) {
	cleanName := filepath.Base(newFilename)
	cleanName = strings.TrimSpace(cleanName)
	if cleanName == "" {
		return nil, errors.New("empty filename")
	}

	var dto *OwnerFileDTO
	now := time.Now().UTC().Format(time.RFC3339)
	newRev := expectedRev + 1

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		meta, err := s.getFileMetadata(tx, f)
		if err != nil {
			return err
		}

		newExt := strings.ToLower(filepath.Ext(cleanName))
		if newExt != strings.ToLower(meta.Extension) {
			return ErrExtensionChange
		}

		meta.Filename = cleanName
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		newMetaPayloadID := uuid.New().String()
		mCtx := crypto.Context{
			PayloadID:       newMetaPayloadID,
			OwnerID:         ownerID,
			FileID:          &f.ID,
			ContentRevision: f.ContentRevision,
		}
		metaVariants, _, err := s.sealVariants(mCtx, metaBytes)
		if err != nil {
			return err
		}

		mRow := storage.PayloadRow{
			ID:              newMetaPayloadID,
			Kind:            "file_metadata",
			ContextOwnerID:  ownerID,
			ContextFileID:   &f.ID,
			ContentRevision: f.ContentRevision,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, mRow, metaVariants); err != nil {
			return err
		}

		if err := s.db.UpdateFileRename(tx, fileID, newMetaPayloadID, expectedRev, newRev, now); err != nil {
			return err
		}

		// Delete old metadata payload
		if err := s.db.DeletePayload(tx, f.MetadataPayloadID); err != nil {
			return err
		}

		username, err := s.getOwnerUsername(tx, ownerID)
		if err != nil {
			return err
		}

		dto = &OwnerFileDTO{
			ID:              f.ID,
			Filename:        cleanName,
			OwnerUsername:   username,
			Revision:        newRev,
			ContentRevision: f.ContentRevision,
			SizeBytes:       f.LogicalBytes,
			Mime:            meta.Mime,
			Variants:        crypto.AllVariantIDs,
			Listed:          f.Listed,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return dto, nil
}

// Replace atomically replaces file content with a fresh revision and revokes all grants and listing.
func (s *Service) Replace(c context.Context, ownerID, fileID string, content []byte, expectedRev int64) (*OwnerFileDTO, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	newRev := expectedRev + 1

	var dto *OwnerFileDTO

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		meta, err := s.getFileMetadata(tx, f)
		if err != nil {
			return err
		}

		typeInfo, effCat, err := ValidateFile(meta.Filename, content, meta.Category)
		if err != nil {
			return err
		}

		meta.Mime = typeInfo.Mime
		meta.Category = effCat
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		newContentRev := f.ContentRevision + 1
		newContentPayloadID := uuid.New().String()
		newMetaPayloadID := uuid.New().String()

		cCtx := crypto.Context{
			PayloadID:       newContentPayloadID,
			OwnerID:         ownerID,
			FileID:          &f.ID,
			ContentRevision: newContentRev,
		}
		contentVariants, contentPhysicalBytes, err := s.sealVariants(cCtx, content)
		if err != nil {
			return err
		}

		mCtx := crypto.Context{
			PayloadID:       newMetaPayloadID,
			OwnerID:         ownerID,
			FileID:          &f.ID,
			ContentRevision: newContentRev,
		}
		metaVariants, metaPhysicalBytes, err := s.sealVariants(mCtx, metaBytes)
		if err != nil {
			return err
		}

		logicalBytes := int64(len(content))
		physicalBytes := contentPhysicalBytes + metaPhysicalBytes

		// Check quotas (old revision content is replaced)
		usage, err := s.db.GetUserQuotas(tx, ownerID)
		if err != nil {
			return err
		}
		if usage.LogicalUsedBytes-f.LogicalBytes+logicalBytes > 100*1024*1024 {
			return ErrQuotaExceeded
		}
		if usage.PhysicalUsedBytes-f.PhysicalBytes+physicalBytes > 2*1024*1024*1024 {
			return ErrQuotaExceeded
		}

		cRow := storage.PayloadRow{
			ID:              newContentPayloadID,
			Kind:            "file_content",
			ContextOwnerID:  ownerID,
			ContextFileID:   &f.ID,
			ContentRevision: newContentRev,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, cRow, contentVariants); err != nil {
			return err
		}

		mRow := storage.PayloadRow{
			ID:              newMetaPayloadID,
			Kind:            "file_metadata",
			ContextOwnerID:  ownerID,
			ContextFileID:   &f.ID,
			ContentRevision: newContentRev,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, mRow, metaVariants); err != nil {
			return err
		}

		if err := s.db.UpdateFileContent(tx, fileID, newContentPayloadID, newMetaPayloadID, newContentRev, expectedRev, newRev, logicalBytes, physicalBytes, now); err != nil {
			return err
		}

		// Delete old payloads
		if err := s.db.DeletePayload(tx, f.ContentPayloadID); err != nil {
			return err
		}
		if err := s.db.DeletePayload(tx, f.MetadataPayloadID); err != nil {
			return err
		}

		username, err := s.getOwnerUsername(tx, ownerID)
		if err != nil {
			return err
		}

		dto = &OwnerFileDTO{
			ID:              f.ID,
			Filename:        meta.Filename,
			OwnerUsername:   username,
			Revision:        newRev,
			ContentRevision: newContentRev,
			SizeBytes:       logicalBytes,
			Mime:            meta.Mime,
			Variants:        crypto.AllVariantIDs,
			Listed:          false,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return dto, nil
}

// Delete permanently deletes the file, its content and metadata payloads, variants, and grants.
func (s *Service) Delete(c context.Context, ownerID, fileID string, expectedRev int64) error {
	return s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		return s.db.DeleteFile(tx, fileID)
	})
}

// SetListing toggles whether file metadata is listed on the public homepage.
func (s *Service) SetListing(c context.Context, ownerID, fileID string, listed bool, expectedRev int64) (*OwnerFileDTO, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	newRev := expectedRev + 1
	var dto *OwnerFileDTO

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		if err := s.db.UpdateFileListing(tx, fileID, listed, expectedRev, newRev, now); err != nil {
			return err
		}

		meta, err := s.getFileMetadata(tx, f)
		if err != nil {
			return err
		}

		username, err := s.getOwnerUsername(tx, ownerID)
		if err != nil {
			return err
		}

		dto = &OwnerFileDTO{
			ID:              f.ID,
			Filename:        meta.Filename,
			OwnerUsername:   username,
			Revision:        newRev,
			ContentRevision: f.ContentRevision,
			SizeBytes:       f.LogicalBytes,
			Mime:            meta.Mime,
			Variants:        crypto.AllVariantIDs,
			Listed:          listed,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return dto, nil
}

// GetFileDetail returns role-filtered FileDetail based on caller permissions.
func (s *Service) GetFileDetail(c context.Context, callerID, fileID string) (interface{}, int64, error) {
	var result interface{}
	var revision int64

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrFileNotFound
		}

		grant, _ := s.db.GetGrant(tx, fileID, callerID)
		perm := sharing.EvaluatePermissions(callerID, f, grant)
		if !perm.CanViewMetadata {
			return ErrFileNotFound
		}

		meta, err := s.getFileMetadata(tx, f)
		if err != nil {
			return err
		}

		username, err := s.getOwnerUsername(tx, f.OwnerID)
		if err != nil {
			return err
		}

		revision = f.Revision

		if perm.IsOwner {
			result = OwnerFileDTO{
				ID:              f.ID,
				Filename:        meta.Filename,
				OwnerUsername:   username,
				Revision:        f.Revision,
				ContentRevision: f.ContentRevision,
				SizeBytes:       f.LogicalBytes,
				Mime:            meta.Mime,
				Variants:        crypto.AllVariantIDs,
				Listed:          f.Listed,
			}
		} else if perm.CanDownload {
			result = DownloadFileDTO{
				ID:              f.ID,
				Filename:        meta.Filename,
				OwnerUsername:   username,
				Revision:        f.Revision,
				ContentRevision: f.ContentRevision,
				SizeBytes:       f.LogicalBytes,
				Mime:            meta.Mime,
				Variants:        crypto.AllVariantIDs,
			}
		} else {
			result = MetadataDTO{
				ID:            f.ID,
				Filename:      meta.Filename,
				OwnerUsername: username,
			}
		}
		return nil
	})

	if err != nil {
		return nil, 0, err
	}
	return result, revision, nil
}

func (s *Service) ListMine(c context.Context, ownerID string, offset, limit int) ([]OwnerFileDTO, int, error) {
	var list []OwnerFileDTO
	var total int

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		rows, tot, err := s.db.ListFilesMine(tx, ownerID, offset, limit)
		if err != nil {
			return err
		}
		total = tot

		username, err := s.getOwnerUsername(tx, ownerID)
		if err != nil {
			return err
		}

		for _, f := range rows {
			meta, err := s.getFileMetadata(tx, &f)
			if err != nil {
				continue
			}
			list = append(list, OwnerFileDTO{
				ID:              f.ID,
				Filename:        meta.Filename,
				OwnerUsername:   username,
				Revision:        f.Revision,
				ContentRevision: f.ContentRevision,
				SizeBytes:       f.LogicalBytes,
				Mime:            meta.Mime,
				Variants:        crypto.AllVariantIDs,
				Listed:          f.Listed,
			})
		}
		return nil
	})

	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (s *Service) ListShared(c context.Context, recipientID string, offset, limit int) ([]interface{}, int, error) {
	var list []interface{}
	var total int

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		rows, tot, err := s.db.ListFilesShared(tx, recipientID, offset, limit)
		if err != nil {
			return err
		}
		total = tot

		for _, f := range rows {
			meta, err := s.getFileMetadata(tx, &f)
			if err != nil {
				continue
			}
			username, err := s.getOwnerUsername(tx, f.OwnerID)
			if err != nil {
				continue
			}

			grant, _ := s.db.GetGrant(tx, f.ID, recipientID)
			if grant != nil && grant.Download {
				list = append(list, DownloadFileDTO{
					ID:              f.ID,
					Filename:        meta.Filename,
					OwnerUsername:   username,
					Revision:        f.Revision,
					ContentRevision: f.ContentRevision,
					SizeBytes:       f.LogicalBytes,
					Mime:            meta.Mime,
					Variants:        crypto.AllVariantIDs,
				})
			} else {
				list = append(list, MetadataDTO{
					ID:            f.ID,
					Filename:      meta.Filename,
					OwnerUsername: username,
				})
			}
		}
		return nil
	})

	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

func (s *Service) ListListed(c context.Context, offset, limit int) ([]MetadataDTO, int, error) {
	var list []MetadataDTO
	var total int

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		rows, tot, err := s.db.ListFilesListed(tx, offset, limit)
		if err != nil {
			return err
		}
		total = tot

		for _, f := range rows {
			meta, err := s.getFileMetadata(tx, &f)
			if err != nil {
				continue
			}
			username, err := s.getOwnerUsername(tx, f.OwnerID)
			if err != nil {
				continue
			}

			list = append(list, MetadataDTO{
				ID:            f.ID,
				Filename:      meta.Filename,
				OwnerUsername: username,
			})
		}
		return nil
	})

	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

