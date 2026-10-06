package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ciphervault.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	profilePayloadID := "payload-profile-1"
	userID := "user-1"
	now := time.Now().UTC().Format(time.RFC3339)

	var variants []PayloadVariantRow
	for _, vID := range []string{
		"aes-128-cbc", "aes-128-cfb128", "aes-128-ofb", "aes-128-ctr",
		"aes-192-cbc", "aes-192-cfb128", "aes-192-ofb", "aes-192-ctr",
		"aes-256-cbc", "aes-256-cfb128", "aes-256-ofb", "aes-256-ctr",
		"des-cbc", "rc4-256",
	} {
		variants = append(variants, PayloadVariantRow{
			PayloadID:     profilePayloadID,
			VariantID:     vID,
			Envelope:      []byte("dummy envelope bytes for " + vID),
			EnvelopeBytes: 100,
		})
	}

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		return db.CreatePayloadWithVariants(tx, PayloadRow{
			ID:              profilePayloadID,
			Kind:            "profile",
			ContextOwnerID:  userID,
			ContextFileID:   nil,
			ContentRevision: 1,
			CreatedAt:       now,
		}, variants)
	})
	if err != nil {
		t.Fatalf("CreatePayloadWithVariants failed: %v", err)
	}

	u := UserRow{
		ID:               userID,
		UsernameLookup:   []byte("lookup-alice"),
		EmailLookup:      []byte("lookup-alice-email"),
		PasswordHash:     "$argon2id$v=19$...",
		ProfilePayloadID: profilePayloadID,
		Revision:         1,
		CreatedAt:        now,
	}
	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		return db.CreateUser(tx, u)
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		return db.CreateUser(tx, u)
	})
	if err != ErrConflict {
		t.Fatalf("expected ErrConflict on duplicate username lookup, got %v", err)
	}

	tokenHash := []byte("session-token-hash-1")
	csrfHash := []byte("csrf-token-hash-1")
	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		return db.CreateSession(tx, SessionRow{
			TokenHash:     tokenHash,
			UserID:        userID,
			CSRFTokenHash: csrfHash,
			CreatedAt:     now,
			ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		})
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		s, err := db.GetSession(tx, tokenHash)
		if err != nil {
			return err
		}
		if s.UserID != userID {
			t.Errorf("expected userID %s, got %s", userID, s.UserID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		return db.DeleteUser(tx, userID)
	})
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := db.GetUserByID(tx, userID)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound for deleted user, got %v", err)
		}
		_, err = db.GetPayload(tx, profilePayloadID)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound for deleted profile payload, got %v", err)
		}
		_, err = db.GetSession(tx, tokenHash)
		if err != ErrNotFound {
			t.Fatalf("expected ErrNotFound for deleted session, got %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

