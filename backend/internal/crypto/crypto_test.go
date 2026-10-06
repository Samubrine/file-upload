package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
)

func TestAllVariantsRoundtrip(t *testing.T) {
	rootKeyID := "test-key-1"
	rootKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rootKey); err != nil {
		t.Fatal(err)
	}
	kp := NewMemoryKeyProvider(map[string][]byte{rootKeyID: rootKey})

	fileIDStr := "file-12345"
	ctx := Context{
		PayloadID:       "payload-12345",
		OwnerID:         "owner-12345",
		FileID:          &fileIDStr,
		ContentRevision: 1,
	}

	testPayloads := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("1234567"),         // 7 bytes (DES block - 1)
		[]byte("12345678"),        // 8 bytes (DES block)
		[]byte("123456789"),       // 9 bytes (DES block + 1)
		[]byte("123456789012345"), // 15 bytes (AES block - 1)
		[]byte("1234567890123456"),// 16 bytes (AES block)
		[]byte("12345678901234567"),// 17 bytes (AES block + 1)
		bytes.Repeat([]byte("A"), 1024),
		bytes.Repeat([]byte("B"), 65536),
	}

	for _, variantID := range AllVariantIDs {
		t.Run(variantID, func(t *testing.T) {
			ctx.VariantID = variantID
			for _, pt := range testPayloads {
				env, timings, err := Seal(ctx, rootKeyID, rootKey, pt)
				if err != nil {
					t.Fatalf("Seal failed for %s with len %d: %v", variantID, len(pt), err)
				}
				decrypted, openTimings, err := Open(ctx, kp, env)
				if err != nil {
					t.Fatalf("Open failed for %s with len %d: %v", variantID, len(pt), err)
				}
				if timings.SealTotalDuration < 0 || openTimings.OpenTotalDuration < 0 {
					t.Errorf("expected non-negative timings")
				}
				if !bytes.Equal(pt, decrypted) {
					t.Fatalf("decrypted bytes mismatch for %s with len %d", variantID, len(pt))
				}
			}
		})
	}
}

func TestTamperDetection(t *testing.T) {
	rootKeyID := "test-key-1"
	rootKey := make([]byte, 32)
	io.ReadFull(rand.Reader, rootKey)
	kp := NewMemoryKeyProvider(map[string][]byte{rootKeyID: rootKey})

	ctx := Context{
		PayloadID:       "payload-1",
		OwnerID:         "owner-1",
		FileID:          nil,
		ContentRevision: 1,
		VariantID:       VariantAES256CTR,
	}

	plaintext := []byte("secret information payload")
	envelope, _, err := Seal(ctx, rootKeyID, rootKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Mutate magic bytes
	tampered := bytes.Clone(envelope)
	tampered[0] ^= 0xFF
	if _, _, err := Open(ctx, kp, tampered); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on corrupted magic, got %v", err)
	}

	// 2. Mutate version
	tampered = bytes.Clone(envelope)
	tampered[4] = 0x99
	if _, _, err := Open(ctx, kp, tampered); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on corrupted version, got %v", err)
	}

	// 3. Mutate header JSON
	tampered = bytes.Clone(envelope)
	tampered[12] ^= 0x01
	if _, _, err := Open(ctx, kp, tampered); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on corrupted header, got %v", err)
	}

	// 4. Mutate ciphertext
	tampered = bytes.Clone(envelope)
	tampered[len(tampered)-35] ^= 0x01
	if _, _, err := Open(ctx, kp, tampered); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on corrupted ciphertext, got %v", err)
	}

	// 5. Mutate HMAC tag
	tampered = bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := Open(ctx, kp, tampered); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on corrupted tag, got %v", err)
	}

	// 6. Swap context (different owner)
	swappedCtx := ctx
	swappedCtx.OwnerID = "owner-hacker"
	if _, _, err := Open(swappedCtx, kp, envelope); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on swapped owner, got %v", err)
	}

	// 7. Swap context (different revision)
	swappedCtx = ctx
	swappedCtx.ContentRevision = 2
	if _, _, err := Open(swappedCtx, kp, envelope); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on swapped revision, got %v", err)
	}

	// 8. Swap context (different variant)
	swappedCtx = ctx
	swappedCtx.VariantID = VariantAES128CBC
	if _, _, err := Open(swappedCtx, kp, envelope); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on swapped variant, got %v", err)
	}

	// 9. Wrong root key
	wrongKp := NewMemoryKeyProvider(map[string][]byte{
		rootKeyID: bytes.Repeat([]byte{0x42}, 32),
	})
	if _, _, err := Open(ctx, wrongKp, envelope); err != ErrIntegrityCheckFailed {
		t.Errorf("expected integrity error on wrong root key, got %v", err)
	}
}

func TestConcurrentRC4Isolation(t *testing.T) {
	rootKeyID := "test-key-1"
	rootKey := make([]byte, 32)
	io.ReadFull(rand.Reader, rootKey)
	kp := NewMemoryKeyProvider(map[string][]byte{rootKeyID: rootKey})

	ctx := Context{
		PayloadID:       "payload-rc4",
		OwnerID:         "owner-1",
		ContentRevision: 1,
		VariantID:       VariantRC4256,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pt := bytes.Repeat([]byte{byte(idx)}, 512)
			env, _, err := Seal(ctx, rootKeyID, rootKey, pt)
			if err != nil {
				t.Errorf("concurrent seal error: %v", err)
				return
			}
			dec, _, err := Open(ctx, kp, env)
			if err != nil {
				t.Errorf("concurrent open error: %v", err)
				return
			}
			if !bytes.Equal(pt, dec) {
				t.Errorf("concurrent roundtrip mismatch")
			}
		}(i)
	}
	wg.Wait()
}

func TestDESWeakKeyTable(t *testing.T) {
	weakKeys := [][]byte{
		{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
		{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
		{0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
		{0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
		{0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
	}
	for _, k := range weakKeys {
		if !IsDESWeakKey(k) {
			t.Errorf("expected key %x to be flagged as weak", k)
		}
	}

	nonWeakKey := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	if IsDESWeakKey(nonWeakKey) {
		t.Errorf("expected normal key not to be weak")
	}
}

func TestDifferentEnvelopesForIdenticalPlaintext(t *testing.T) {
	rootKeyID := "test-key-1"
	rootKey := make([]byte, 32)
	io.ReadFull(rand.Reader, rootKey)

	ctx := Context{
		PayloadID:       "payload-dup",
		OwnerID:         "owner-dup",
		ContentRevision: 1,
		VariantID:       VariantAES256CTR,
	}

	pt := []byte("identical plaintext message")
	env1, _, err := Seal(ctx, rootKeyID, rootKey, pt)
	if err != nil {
		t.Fatal(err)
	}
	env2, _, err := Seal(ctx, rootKeyID, rootKey, pt)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(env1, env2) {
		t.Errorf("expected different envelopes due to fresh random salts and IVs")
	}
}

func TestKnownAnswerVectors(t *testing.T) {
	// NIST SP 800-38A AES-128-CBC known vector
	// Key: 2b7e151628aed2a6abf7158809cf4f3c
	// IV:  000102030405060708090a0b0c0d0e0f
	// Plaintext: 6bc1bee22e409f96e93d7e117393172a
	// Ciphertext: 7649abac8119b246cee98e9b12e9197d
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	pt := []byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}
	expectedCT := []byte{0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d}

	spec, _ := GetVariant(VariantAES128CBC)
	ct, err := encryptPlaintext(spec, key, iv, pt)
	if err != nil {
		t.Fatal(err)
	}
	// First 16 bytes of ct (before PKCS7 padding block) should match NIST vector
	if !bytes.Equal(ct[:16], expectedCT) {
		t.Errorf("AES-128-CBC vector mismatch. got %x, want %x", ct[:16], expectedCT)
	}
}

func TestPKCS7PaddingValidation(t *testing.T) {
	// Valid padding
	data := []byte("hello")
	padded, err := PKCS7Pad(data, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(padded))
	}
	unpadded, err := PKCS7Unpad(padded, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Errorf("unpad mismatch")
	}

	// Corrupt padding byte
	corrupt := bytes.Clone(padded)
	corrupt[len(corrupt)-2] = 0x00
	if _, err := PKCS7Unpad(corrupt, 16); err != ErrInvalidPadding {
		t.Errorf("expected ErrInvalidPadding on corrupted padding byte, got %v", err)
	}

	// Invalid padding length (0)
	corrupt = bytes.Clone(padded)
	corrupt[len(corrupt)-1] = 0x00
	if _, err := PKCS7Unpad(corrupt, 16); err != ErrInvalidPadding {
		t.Errorf("expected ErrInvalidPadding on 0 padding byte, got %v", err)
	}

	// Invalid padding length (> blockSize)
	corrupt = bytes.Clone(padded)
	corrupt[len(corrupt)-1] = 17
	if _, err := PKCS7Unpad(corrupt, 16); err != ErrInvalidPadding {
		t.Errorf("expected ErrInvalidPadding on >blockSize padding byte, got %v", err)
	}
}


