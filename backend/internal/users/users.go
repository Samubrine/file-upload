package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ciphervault/internal/auth"
	"ciphervault/internal/crypto"
	"ciphervault/internal/storage"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput       = errors.New("invalid input data")
	ErrPasswordMismatch   = errors.New("invalid current password")
	ErrUserNotFound       = errors.New("user not found")
	ErrNoticeRequired     = errors.New("privacy notice must be acknowledged")
	ErrPasswordComplexity = errors.New("password must be between 12 and 128 characters")
)

const (
	CurrentNoticeVersion = "1.0"
	LogicalQuotaBytes    = 100 * 1024 * 1024       // 100 MiB
	PhysicalQuotaBytes   = 2 * 1024 * 1024 * 1024  // 2 GiB
	FileCountLimit       = 100
)

type Profile struct {
	FullName string  `json:"full_name"`
	Username string  `json:"username"`
	Email    string  `json:"email"`
	Birthday *string `json:"birthday"`
}

type RegisterInput struct {
	FullName           string  `json:"full_name"`
	Username           string  `json:"username"`
	Email              string  `json:"email"`
	Birthday           *string `json:"birthday"`
	Password           string  `json:"password"`
	NoticeVersion      string  `json:"notice_version"`
	NoticeAcknowledged bool    `json:"notice_acknowledged"`
}

type ProfileUpdateInput struct {
	FullName        string  `json:"full_name"`
	Email           string  `json:"email"`
	Birthday        *string `json:"birthday"`
	CurrentPassword string  `json:"current_password"`
}

type Service struct {
	db               *storage.DB
	keyProvider      crypto.KeyProvider
	activeRootKeyID  string
	identityIndexKey []byte
}

func NewService(db *storage.DB, kp crypto.KeyProvider, activeRootKeyID string, identityIndexKey []byte) *Service {
	return &Service{
		db:               db,
		keyProvider:      kp,
		activeRootKeyID:  activeRootKeyID,
		identityIndexKey: identityIndexKey,
	}
}

func ValidatePassword(p string) error {
	runes := []rune(p)
	if len(runes) < 12 || len(runes) > 128 || len([]byte(p)) > 512 {
		return ErrPasswordComplexity
	}
	return nil
}

func ValidateBirthday(b *string) error {
	if b == nil || *b == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", *b)
	if err != nil {
		return errors.New("birthday must be YYYY-MM-DD")
	}
	today := time.Now().UTC().Format("2006-01-02")
	todayTime, _ := time.Parse("2006-01-02", today)
	if t.After(todayTime) {
		return errors.New("birthday cannot be in the future")
	}
	return nil
}

// SealProfileVariants generates 14 independently sealed variants of the profile JSON.
func (s *Service) SealProfileVariants(ctx crypto.Context, p Profile) ([]storage.PayloadVariantRow, error) {
	rootKey, err := s.keyProvider.GetRootKey(s.activeRootKeyID)
	if err != nil {
		return nil, fmt.Errorf("active root key not available: %w", err)
	}

	payloadBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	variants := make([]storage.PayloadVariantRow, 0, len(crypto.AllVariantIDs))
	for _, vID := range crypto.AllVariantIDs {
		vCtx := ctx
		vCtx.VariantID = vID

		env, _, err := crypto.Seal(vCtx, s.activeRootKeyID, rootKey, payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to seal profile variant %s: %w", vID, err)
		}

		variants = append(variants, storage.PayloadVariantRow{
			PayloadID:     ctx.PayloadID,
			VariantID:     vID,
			Envelope:      env,
			EnvelopeBytes: int64(len(env)),
		})
	}

	return variants, nil
}

// Register creates a new user, profile payload with 14 variants, and initial session.
func (s *Service) Register(c context.Context, input RegisterInput) (*storage.UserRow, *Profile, string, string, error) {
	if !input.NoticeAcknowledged || input.NoticeVersion != CurrentNoticeVersion {
		return nil, nil, "", "", ErrNoticeRequired
	}
	if len(input.FullName) == 0 || len(input.FullName) > 100 {
		return nil, nil, "", "", errors.New("full name must be between 1 and 100 characters")
	}
	if !auth.ValidateUsername(input.Username) {
		return nil, nil, "", "", errors.New("username must be 3-32 characters, lowercase alphanumeric or underscore")
	}
	if !auth.ValidateEmail(input.Email) {
		return nil, nil, "", "", errors.New("invalid email address")
	}
	if err := ValidateBirthday(input.Birthday); err != nil {
		return nil, nil, "", "", err
	}
	if err := ValidatePassword(input.Password); err != nil {
		return nil, nil, "", "", err
	}

	cleanUsername := auth.NormalizeUsername(input.Username)
	cleanEmail := auth.NormalizeEmail(input.Email)

	pwdHash, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, nil, "", "", err
	}

	userID := uuid.New().String()
	payloadID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	profile := Profile{
		FullName: input.FullName,
		Username: cleanUsername,
		Email:    cleanEmail,
		Birthday: input.Birthday,
	}

	pCtx := crypto.Context{
		PayloadID:       payloadID,
		OwnerID:         userID,
		FileID:          nil,
		ContentRevision: 1,
	}

	variants, err := s.SealProfileVariants(pCtx, profile)
	if err != nil {
		return nil, nil, "", "", err
	}

	rawSession, sessionHash, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, nil, "", "", err
	}
	rawCSRF, csrfHash, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, nil, "", "", err
	}

	var createdUser storage.UserRow
	err = s.db.WithTx(c, func(tx *sql.Tx) error {
		pRow := storage.PayloadRow{
			ID:              payloadID,
			Kind:            "profile",
			ContextOwnerID:  userID,
			ContextFileID:   nil,
			ContentRevision: 1,
			CreatedAt:       now,
		}
		if err := s.db.CreatePayloadWithVariants(tx, pRow, variants); err != nil {
			return err
		}

		uRow := storage.UserRow{
			ID:               userID,
			UsernameLookup:   auth.ComputeUsernameLookup(s.identityIndexKey, cleanUsername),
			EmailLookup:      auth.ComputeEmailLookup(s.identityIndexKey, cleanEmail),
			PasswordHash:     pwdHash,
			ProfilePayloadID: payloadID,
			Revision:         1,
			CreatedAt:        now,
		}
		if err := s.db.CreateUser(tx, uRow); err != nil {
			return err
		}
		createdUser = uRow

		sRow := storage.SessionRow{
			TokenHash:     sessionHash,
			UserID:        userID,
			CSRFTokenHash: csrfHash,
			CreatedAt:     now,
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		}
		return s.db.CreateSession(tx, sRow)
	})

	if err != nil {
		return nil, nil, "", "", err
	}

	return &createdUser, &profile, rawSession, rawCSRF, nil
}

// Login authenticates credentials and creates a session.
func (s *Service) Login(c context.Context, username, password string) (*storage.UserRow, *Profile, string, string, error) {
	cleanUsername := auth.NormalizeUsername(username)
	lookup := auth.ComputeUsernameLookup(s.identityIndexKey, cleanUsername)

	var uRow *storage.UserRow
	var profile *Profile

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserByUsernameLookup(tx, lookup)
		if err != nil {
			return errors.New("invalid credentials")
		}
		uRow = u

		match, err := auth.VerifyPassword(password, u.PasswordHash)
		if err != nil || !match {
			return errors.New("invalid credentials")
		}

		prof, err := s.decryptProfile(tx, u)
		if err != nil {
			return err
		}
		profile = prof
		return nil
	})
	if err != nil {
		return nil, nil, "", "", err
	}

	rawSession, sessionHash, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, nil, "", "", err
	}
	rawCSRF, csrfHash, err := auth.GenerateRandomToken()
	if err != nil {
		return nil, nil, "", "", err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	err = s.db.WithTx(c, func(tx *sql.Tx) error {
		sRow := storage.SessionRow{
			TokenHash:     sessionHash,
			UserID:        uRow.ID,
			CSRFTokenHash: csrfHash,
			CreatedAt:     now,
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		}
		return s.db.CreateSession(tx, sRow)
	})
	if err != nil {
		return nil, nil, "", "", err
	}

	return uRow, profile, rawSession, rawCSRF, nil
}

func (s *Service) GetProfile(c context.Context, userID string) (*Profile, int64, error) {
	var profile *Profile
	var rev int64

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserByID(tx, userID)
		if err != nil {
			return err
		}
		rev = u.Revision
		prof, err := s.decryptProfile(tx, u)
		if err != nil {
			return err
		}
		profile = prof
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return profile, rev, nil
}

func (s *Service) decryptProfile(tx *sql.Tx, u *storage.UserRow) (*Profile, error) {
	// Read default variant
	variantRow, err := s.db.GetPayloadVariant(tx, u.ProfilePayloadID, crypto.DefaultVariant)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile variant: %w", err)
	}

	ctx := crypto.Context{
		PayloadID:       u.ProfilePayloadID,
		OwnerID:         u.ID,
		FileID:          nil,
		ContentRevision: 1,
		VariantID:       crypto.DefaultVariant,
	}

	plaintext, _, err := crypto.Open(ctx, s.keyProvider, variantRow.Envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to open profile envelope: %w", err)
	}

	var p Profile
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}
	return &p, nil
}

func (s *Service) UpdateProfile(c context.Context, userID string, expectedRev int64, input ProfileUpdateInput) (*Profile, int64, error) {
	if len(input.FullName) == 0 || len(input.FullName) > 100 {
		return nil, 0, errors.New("full name must be between 1 and 100 characters")
	}
	if !auth.ValidateEmail(input.Email) {
		return nil, 0, errors.New("invalid email address")
	}
	if err := ValidateBirthday(input.Birthday); err != nil {
		return nil, 0, err
	}

	cleanEmail := auth.NormalizeEmail(input.Email)
	newEmailLookup := auth.ComputeEmailLookup(s.identityIndexKey, cleanEmail)

	var updatedProfile *Profile
	newRev := expectedRev + 1

	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserByID(tx, userID)
		if err != nil {
			return err
		}
		match, err := auth.VerifyPassword(input.CurrentPassword, u.PasswordHash)
		if err != nil || !match {
			return ErrPasswordMismatch
		}

		oldProfile, err := s.decryptProfile(tx, u)
		if err != nil {
			return err
		}

		newProfile := Profile{
			FullName: input.FullName,
			Username: oldProfile.Username, // Username is immutable
			Email:    cleanEmail,
			Birthday: input.Birthday,
		}

		newPayloadID := uuid.New().String()
		pCtx := crypto.Context{
			PayloadID:       newPayloadID,
			OwnerID:         userID,
			FileID:          nil,
			ContentRevision: 1,
		}

		variants, err := s.SealProfileVariants(pCtx, newProfile)
		if err != nil {
			return err
		}

		pRow := storage.PayloadRow{
			ID:              newPayloadID,
			Kind:            "profile",
			ContextOwnerID:  userID,
			ContextFileID:   nil,
			ContentRevision: 1,
			CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		}
		if err := s.db.CreatePayloadWithVariants(tx, pRow, variants); err != nil {
			return err
		}

		if err := s.db.UpdateUserProfile(tx, userID, newEmailLookup, newPayloadID, expectedRev, newRev); err != nil {
			return err
		}

		// Delete old payload
		if err := s.db.DeletePayload(tx, u.ProfilePayloadID); err != nil {
			return err
		}

		updatedProfile = &newProfile
		return nil
	})

	if err != nil {
		return nil, 0, err
	}
	return updatedProfile, newRev, nil
}

func (s *Service) UpdatePassword(c context.Context, userID string, expectedRev int64, currentPassword, newPassword string, currentTokenHash []byte) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	newRev := expectedRev + 1
	return s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserByID(tx, userID)
		if err != nil {
			return err
		}
		match, err := auth.VerifyPassword(currentPassword, u.PasswordHash)
		if err != nil || !match {
			return ErrPasswordMismatch
		}

		if err := s.db.UpdateUserPassword(tx, userID, newHash, expectedRev, newRev); err != nil {
			return err
		}

		// Invalidate all other sessions
		return s.db.DeleteOtherSessions(tx, userID, currentTokenHash)
	})
}

func (s *Service) DeleteAccount(c context.Context, userID string, currentPassword string) error {
	return s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserByID(tx, userID)
		if err != nil {
			return err
		}
		match, err := auth.VerifyPassword(currentPassword, u.PasswordHash)
		if err != nil || !match {
			return ErrPasswordMismatch
		}

		return s.db.DeleteUser(tx, userID)
	})
}

func (s *Service) GetQuota(c context.Context, userID string) (*storage.QuotaUsage, error) {
	var usage *storage.QuotaUsage
	err := s.db.WithTx(c, func(tx *sql.Tx) error {
		u, err := s.db.GetUserQuotas(tx, userID)
		if err != nil {
			return err
		}
		usage = u
		return nil
	})
	return usage, err
}

