package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidHash         = errors.New("invalid password hash format")
	ErrIncompatibleVersion = errors.New("incompatible hash version")
	ErrPasswordTooLong     = errors.New("password exceeds 72 bytes")
)

// MaxPasswordBytes is bcrypt's input limit. Longer passwords are rejected rather
// than truncated, because truncation lets any suffix authenticate.
const MaxPasswordBytes = 72

// HashPassword generates a standard bcrypt hash string from password.
func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash failure: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies that a plaintext password matches either bcrypt or Argon2id.
func VerifyPassword(password, encodedHash string) (bool, error) {
	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") || strings.HasPrefix(encodedHash, "$2y$") {
		if len(password) > MaxPasswordBytes {
			// Still spend a comparison so overlong attempts are not faster.
			_ = bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password[:MaxPasswordBytes]))
			return false, nil
		}
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		if err != nil {
			return false, nil
		}
		return true, nil
	}

	if strings.HasPrefix(encodedHash, "$argon2id$") {
		return verifyArgon2(password, encodedHash)
	}

	return false, ErrInvalidHash
}

func verifyArgon2(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8

	subparts := strings.Split(parts[3], ",")
	if len(subparts) != 3 {
		return false, ErrInvalidHash
	}
	for _, p := range subparts {
		kv := strings.Split(p, "=")
		if len(kv) != 2 {
			return false, ErrInvalidHash
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false, ErrInvalidHash
		}
		switch kv[0] {
		case "m":
			memory = uint32(val)
		case "t":
			iterations = uint32(val)
		case "p":
			parallelism = uint8(val)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1, nil
}

