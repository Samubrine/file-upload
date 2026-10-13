package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// V1: with no key environment variables the server must not fall back to
// constant keys; it generates random keys once and persists them locally.
func TestV1DevKeysGeneratedPersistedAndNotConstant(t *testing.T) {
	dir := t.TempDir()
	noEnv := func(string) string { return "" }

	root1, index1, err := loadKeys(dir, "root-1", noEnv)
	if err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if len(root1) != 32 || len(index1) != 32 {
		t.Fatalf("expected 32-byte keys, got %d and %d", len(root1), len(index1))
	}
	if bytes.Equal(root1, index1) {
		t.Fatal("root and index keys must differ")
	}
	for _, legacy := range []string{"ciphervault_dev_root_key_32_byte", "ciphervault_dev_index_key_32_byt"} {
		if bytes.Equal(root1, []byte(legacy)) || bytes.Equal(index1, []byte(legacy)) {
			t.Fatal("generated key equals a legacy hardcoded constant")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "dev-keys.json")); err != nil {
		t.Fatalf("expected dev-keys.json to be written: %v", err)
	}

	root2, index2, err := loadKeys(dir, "root-1", noEnv)
	if err != nil {
		t.Fatalf("second loadKeys: %v", err)
	}
	if !bytes.Equal(root1, root2) || !bytes.Equal(index1, index2) {
		t.Fatal("keys must be reused from dev-keys.json on later runs")
	}

	other, _, err := loadKeys(t.TempDir(), "root-1", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(root1, other) {
		t.Fatal("two fresh data directories produced the same root key")
	}
}

func TestV1EnvKeysTakePriority(t *testing.T) {
	dir := t.TempDir()
	rootHex := hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	indexHex := hex.EncodeToString(bytes.Repeat([]byte{0xCD}, 32))
	env := map[string]string{"CRYPTO_ROOT_KEY_root-1": rootHex, "IDENTITY_INDEX_KEY": indexHex}

	root, index, err := loadKeys(dir, "root-1", func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if hex.EncodeToString(root) != rootHex || hex.EncodeToString(index) != indexHex {
		t.Fatal("environment keys must take priority")
	}
	if _, err := os.Stat(filepath.Join(dir, "dev-keys.json")); !os.IsNotExist(err) {
		t.Fatal("no key file should be written when environment keys are set")
	}
}
