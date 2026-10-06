package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	CookieNameDev  = "ciphervault_session"
	CookieNameProd = "__Host-ciphervault_session"
)

// GenerateRandomToken generates 32 random bytes and returns hex string and its SHA256 hash.
func GenerateRandomToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", nil, fmt.Errorf("failed to generate random token: %w", err)
	}
	raw = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

// HashToken computes the SHA-256 hash of a raw token string.
func HashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// ValidateCSRF compares the SHA-256 hash of rawCSRF against expectedHash in constant time.
func ValidateCSRF(rawCSRF string, expectedHash []byte) bool {
	if rawCSRF == "" || len(expectedHash) == 0 {
		return false
	}
	computed := HashToken(rawCSRF)
	return subtle.ConstantTimeCompare(computed, expectedHash) == 1
}

