package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"regexp"
	"strings"
)

var (
	usernameRegex = regexp.MustCompile("^[a-z0-9_]{3,32}$")
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$`)
)

func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateUsername(username string) bool {
	norm := NormalizeUsername(username)
	return usernameRegex.MatchString(norm)
}

func ValidateEmail(email string) bool {
	norm := NormalizeEmail(email)
	if len(norm) > 254 {
		return false
	}
	return emailRegex.MatchString(norm)
}

// ComputeUsernameLookup derives a deterministic keyed HMAC token for username indexing.
func ComputeUsernameLookup(identityIndexKey []byte, username string) []byte {
	norm := NormalizeUsername(username)
	h := hmac.New(sha256.New, identityIndexKey)
	h.Write([]byte("username:" + norm))
	return h.Sum(nil)
}

// ComputeEmailLookup derives a deterministic keyed HMAC token for email indexing.
func ComputeEmailLookup(identityIndexKey []byte, email string) []byte {
	norm := NormalizeEmail(email)
	h := hmac.New(sha256.New, identityIndexKey)
	h.Write([]byte("email:" + norm))
	return h.Sum(nil)
}

