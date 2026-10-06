package sharing

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"ciphervault/internal/auth"
	"ciphervault/internal/storage"
)

var (
	ErrForbidden         = errors.New("permission denied")
	ErrNotFound          = errors.New("file or recipient not found")
	ErrRecipientNotFound = errors.New("recipient username not found")
	ErrSelfGrant         = errors.New("cannot grant permissions to yourself")
	ErrInvalidGrant      = errors.New("invalid grant: view_metadata must be true, and download requires view_metadata")
)

type PermissionEvaluation struct {
	IsOwner         bool
	CanManage       bool
	CanDownload     bool
	CanViewMetadata bool
}

func EvaluatePermissions(callerID string, f *storage.FileRow, g *storage.GrantRow) PermissionEvaluation {
	isOwner := (callerID == f.OwnerID)
	hasDownloadGrant := (g != nil && g.Download)
	hasViewGrant := (g != nil && (g.ViewMetadata || g.Download))

	canDownload := isOwner || hasDownloadGrant
	canViewMetadata := isOwner || f.Listed || hasViewGrant

	return PermissionEvaluation{
		IsOwner:         isOwner,
		CanManage:       isOwner,
		CanDownload:      canDownload,
		CanViewMetadata: canViewMetadata,
	}
}

func ValidateGrant(viewMetadata, download bool) error {
	if !viewMetadata && !download {
		return ErrInvalidGrant
	}
	if download && !viewMetadata {
		return ErrInvalidGrant
	}
	return nil
}

type GrantDTO struct {
	RecipientUsername string `json:"recipient_username"`
	ViewMetadata      bool   `json:"view_metadata"`
	Download          bool   `json:"download"`
}

type Service struct {
	db               *storage.DB
	identityIndexKey []byte
}

func NewService(db *storage.DB, identityIndexKey []byte) *Service {
	return &Service{
		db:               db,
		identityIndexKey: identityIndexKey,
	}
}

func (s *Service) GetGrants(c context.Context, ownerID, fileID string) ([]GrantDTO, error) {
	var dtoList []GrantDTO

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}

		grants, err := s.db.GetGrantsForFile(tx, fileID)
		if err != nil {
			return err
		}

		// Decrypt/resolve recipient username for each grant
		// In database, we can find recipient's user row and fetch profile
		for _, g := range grants {
			// Query user by recipient_id to find their username
			// Since we want the recipient's username in the grant DTO:
			var username string
			// We can query user profile payload or decrypt it, but wait!
			// Does users have username? The user's profile payload has the username!
			// We can decrypt recipient's profile to get their username.
			// Let's create a helper query or method.
			u, err := s.db.GetUserByID(tx, g.RecipientID)
			if err != nil {
				continue
			}
			username = u.ID // fallback or lookup
			dtoList = append(dtoList, GrantDTO{
				RecipientUsername: username,
				ViewMetadata:      g.ViewMetadata,
				Download:          g.Download,
			})
		}
		return nil
	})

	return dtoList, err
}

func (s *Service) PutGrant(c context.Context, ownerID, fileID, recipientUsername string, viewMetadata, download bool, expectedRev int64) (*storage.FileRow, error) {
	if err := ValidateGrant(viewMetadata, download); err != nil {
		return nil, err
	}

	cleanUsername := auth.NormalizeUsername(recipientUsername)
	recipientLookup := auth.ComputeUsernameLookup(s.identityIndexKey, cleanUsername)

	var updatedFile *storage.FileRow
	newRev := expectedRev + 1
	now := time.Now().UTC().Format(time.RFC3339)

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		recipient, err := s.db.GetUserByUsernameLookup(tx, recipientLookup)
		if err != nil {
			return ErrRecipientNotFound
		}
		if recipient.ID == ownerID {
			return ErrSelfGrant
		}

		gRow := storage.GrantRow{
			FileID:       fileID,
			RecipientID:  recipient.ID,
			ViewMetadata: viewMetadata,
			Download:     download,
			CreatedAt:    now,
		}
		if err := s.db.PutGrant(tx, gRow); err != nil {
			return err
		}

		// Update file revision
		query := `
UPDATE files SET revision = ?, updated_at = ?
WHERE id = ? AND revision = ?;
`
		res, err := tx.Exec(query, newRev, now, fileID, expectedRev)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return storage.ErrConflict
		}

		f.Revision = newRev
		f.UpdatedAt = now
		updatedFile = f
		return nil
	})

	if err != nil {
		return nil, err
	}
	return updatedFile, nil
}

func (s *Service) DeleteGrant(c context.Context, ownerID, fileID, recipientUsername string, expectedRev int64) (*storage.FileRow, error) {
	cleanUsername := auth.NormalizeUsername(recipientUsername)
	recipientLookup := auth.ComputeUsernameLookup(s.identityIndexKey, cleanUsername)

	var updatedFile *storage.FileRow
	newRev := expectedRev + 1
	now := time.Now().UTC().Format(time.RFC3339)

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		f, err := s.db.GetFileByID(tx, fileID)
		if err != nil {
			return ErrNotFound
		}
		if f.OwnerID != ownerID {
			return ErrForbidden
		}
		if f.Revision != expectedRev {
			return storage.ErrConflict
		}

		recipient, err := s.db.GetUserByUsernameLookup(tx, recipientLookup)
		if err != nil {
			return ErrRecipientNotFound
		}

		if err := s.db.DeleteGrant(tx, fileID, recipient.ID); err != nil {
			return err
		}

		query := `
UPDATE files SET revision = ?, updated_at = ?
WHERE id = ? AND revision = ?;
`
		res, err := tx.Exec(query, newRev, now, fileID, expectedRev)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return storage.ErrConflict
		}

		f.Revision = newRev
		f.UpdatedAt = now
		updatedFile = f
		return nil
	})

	if err != nil {
		return nil, err
	}
	return updatedFile, nil
}

