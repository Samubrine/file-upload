package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const devKeysFileName = "dev-keys.json"

type devKeyFile struct {
	RootKeys         map[string]string `json:"root_keys"`
	IdentityIndexKey string            `json:"identity_index_key"`
}

// loadKeys resolves the active root key and the identity index key.
// Environment variables take priority. Any key not supplied by the
// environment is read from <dataDir>/dev-keys.json, generating fresh random
// keys on first use. No key material is ever compiled into the binary.
func loadKeys(dataDir, activeKeyID string, getenv func(string) string) (rootKey, indexKey []byte, err error) {
	if v := strings.TrimSpace(getenv("CRYPTO_ROOT_KEY_" + activeKeyID)); v != "" {
		rootKey = normalizeKey32(v)
	}
	if v := strings.TrimSpace(getenv("IDENTITY_INDEX_KEY")); v != "" {
		indexKey = normalizeKey32(v)
	}
	if rootKey != nil && indexKey != nil {
		return rootKey, indexKey, nil
	}

	path := filepath.Join(dataDir, devKeysFileName)
	kf, err := readDevKeyFile(path)
	if err != nil {
		return nil, nil, err
	}
	changed := false
	if kf.RootKeys == nil {
		kf.RootKeys = map[string]string{}
	}
	if _, ok := kf.RootKeys[activeKeyID]; !ok && rootKey == nil {
		k, err := randomKeyHex()
		if err != nil {
			return nil, nil, err
		}
		kf.RootKeys[activeKeyID] = k
		changed = true
	}
	if kf.IdentityIndexKey == "" && indexKey == nil {
		k, err := randomKeyHex()
		if err != nil {
			return nil, nil, err
		}
		kf.IdentityIndexKey = k
		changed = true
	}
	if changed {
		if err := writeDevKeyFile(dataDir, path, kf); err != nil {
			return nil, nil, err
		}
	}
	if rootKey == nil {
		if rootKey, err = decodeKeyHex(kf.RootKeys[activeKeyID]); err != nil {
			return nil, nil, fmt.Errorf("dev-keys.json root key %q: %w", activeKeyID, err)
		}
	}
	if indexKey == nil {
		if indexKey, err = decodeKeyHex(kf.IdentityIndexKey); err != nil {
			return nil, nil, fmt.Errorf("dev-keys.json identity index key: %w", err)
		}
	}
	return rootKey, indexKey, nil
}

func readDevKeyFile(path string) (devKeyFile, error) {
	var kf devKeyFile
	data, err := os.ReadFile(path) // #nosec G304 -- path is <dataDir>/dev-keys.json chosen by the operator
	if errors.Is(err, os.ErrNotExist) {
		return kf, nil
	}
	if err != nil {
		return kf, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &kf); err != nil {
		return kf, fmt.Errorf("parse %s: %w", path, err)
	}
	return kf, nil
}

func writeDevKeyFile(dataDir, path string, kf devKeyFile) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dataDir, err)
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}

func randomKeyHex() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func decodeKeyHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("must be 64 hex characters")
	}
	return b, nil
}

// normalizeKey32 accepts a 64-character hex key, a raw 32-byte string, or any
// other passphrase (stretched with SHA-256) supplied through the environment.
func normalizeKey32(raw string) []byte {
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b
	}
	if len(raw) == 32 {
		return []byte(raw)
	}
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
