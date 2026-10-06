package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	EnvelopeMagic   = []byte{'C', 'V', 'L', 'T'}
	EnvelopeVersion = byte(0x01)
	MaxHeaderLength = 4096
)

type Context struct {
	PayloadID       string
	OwnerID         string
	FileID          *string
	ContentRevision int64
	VariantID       string
}

type Header struct {
	PayloadID       string  `json:"payload_id"`
	OwnerID         string  `json:"owner_id"`
	FileID          *string `json:"file_id"`
	ContentRevision int64   `json:"content_revision"`
	VariantID       string  `json:"variant_id"`
	RootKeyID       string  `json:"root_key_id"`
	Salt            string  `json:"salt"`
	IV              string  `json:"iv"`
	PlaintextBytes  int64   `json:"plaintext_bytes"`
}

type KeyProvider interface {
	GetRootKey(id string) ([]byte, error)
}

type MemoryKeyProvider struct {
	keys map[string][]byte
}

func NewMemoryKeyProvider(keys map[string][]byte) *MemoryKeyProvider {
	cp := make(map[string][]byte, len(keys))
	for k, v := range keys {
		dup := make([]byte, len(v))
		copy(dup, v)
		cp[k] = dup
	}
	return &MemoryKeyProvider{keys: cp}
}

func (m *MemoryKeyProvider) GetRootKey(id string) ([]byte, error) {
	k, ok := m.keys[id]
	if !ok {
		return nil, fmt.Errorf("root key not found for id: %s", id)
	}
	return k, nil
}

type SealTimings struct {
	EncryptCipherDuration time.Duration
	SealTotalDuration     time.Duration
}

type OpenTimings struct {
	KDFDuration           time.Duration
	MACVerifyDuration     time.Duration
	DecryptCipherDuration time.Duration
	OpenTotalDuration     time.Duration
}

func buildHKDFInfo(formatVersion int, payloadID, ownerID string, fileID *string, contentRevision int64, variantID, purpose string) string {
	var fileIDStr string
	if fileID == nil {
		fileIDStr = "null"
	} else {
		fileIDStr = fmt.Sprintf("%q", *fileID)
	}
	return fmt.Sprintf("[%d,%q,%q,%s,%d,%q,%q]", formatVersion, payloadID, ownerID, fileIDStr, contentRevision, variantID, purpose)
}

func deriveKey(rootKey, salt []byte, info string, keyLen int) ([]byte, error) {
	return hkdf.Key(sha256.New, rootKey, salt, info, keyLen)
}

// Seal encrypts and wraps plaintext into an authenticated v1 envelope.
func Seal(ctx Context, rootKeyID string, rootKey []byte, plaintext []byte) ([]byte, *SealTimings, error) {
	totalStart := time.Now()

	spec, err := GetVariant(ctx.VariantID)
	if err != nil {
		return nil, nil, err
	}
	if len(rootKey) != 32 {
		return nil, nil, errors.New("root key must be exactly 32 bytes")
	}

	var salt []byte
	var encKey []byte
	encInfo := buildHKDFInfo(1, ctx.PayloadID, ctx.OwnerID, ctx.FileID, ctx.ContentRevision, ctx.VariantID, "enc")

	for {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random salt: %w", err)
		}

		k, err := deriveKey(rootKey, salt, encInfo, spec.KeyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive enc key: %w", err)
		}

		if spec.Algorithm == AlgoDES {
			if IsDESWeakKey(k) {
				continue // Weak key rejected, regenerate salt
			}
		}
		encKey = k
		break
	}

	macInfo := buildHKDFInfo(1, ctx.PayloadID, ctx.OwnerID, ctx.FileID, ctx.ContentRevision, ctx.VariantID, "mac")
	macKey, err := deriveKey(rootKey, salt, macInfo, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive mac key: %w", err)
	}

	var iv []byte
	if spec.IVBytes > 0 {
		iv = make([]byte, spec.IVBytes)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random iv: %w", err)
		}
	}

	header := Header{
		PayloadID:       ctx.PayloadID,
		OwnerID:         ctx.OwnerID,
		FileID:          ctx.FileID,
		ContentRevision: ctx.ContentRevision,
		VariantID:       ctx.VariantID,
		RootKeyID:       rootKeyID,
		Salt:            base64.StdEncoding.EncodeToString(salt),
		PlaintextBytes:  int64(len(plaintext)),
	}
	if len(iv) > 0 {
		header.IV = base64.StdEncoding.EncodeToString(iv)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	if len(headerJSON) > MaxHeaderLength {
		return nil, nil, fmt.Errorf("header length %d exceeds max %d", len(headerJSON), MaxHeaderLength)
	}

	// Encrypt plaintext
	cipherStart := time.Now()
	ciphertext, err := encryptPlaintext(spec, encKey, iv, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt: %w", err)
	}
	cipherDur := time.Since(cipherStart)

	// Build envelope framing
	// 4 (CVLT) + 1 (ver) + 4 (headerLen) + headerJSON + ciphertext + 32 (HMAC)
	headerLenUint32 := uint32(len(headerJSON))
	envelopeLen := 4 + 1 + 4 + len(headerJSON) + len(ciphertext) + 32
	envelope := make([]byte, envelopeLen)

	copy(envelope[0:4], EnvelopeMagic)
	envelope[4] = EnvelopeVersion
	binary.BigEndian.PutUint32(envelope[5:9], headerLenUint32)
	copy(envelope[9:9+len(headerJSON)], headerJSON)
	copy(envelope[9+len(headerJSON):9+len(headerJSON)+len(ciphertext)], ciphertext)

	// HMAC covers magic + version + headerLen + headerJSON + ciphertext
	macData := envelope[:9+len(headerJSON)+len(ciphertext)]
	h := hmac.New(sha256.New, macKey)
	h.Write(macData)
	tag := h.Sum(nil)
	copy(envelope[len(envelope)-32:], tag)

	timings := &SealTimings{
		EncryptCipherDuration: cipherDur,
		SealTotalDuration:     time.Since(totalStart),
	}

	return envelope, timings, nil
}

// Open authenticates and decrypts a v1 envelope.
func Open(ctx Context, keyProvider KeyProvider, envelope []byte) ([]byte, *OpenTimings, error) {
	totalStart := time.Now()
	timings := &OpenTimings{}

	// Minimum framing: 4 + 1 + 4 + header(min ~100) + ciphertext(min 0 or 8/16) + 32 (HMAC)
	if len(envelope) < 4+1+4+32 {
		return nil, nil, ErrIntegrityCheckFailed
	}

	if subtle.ConstantTimeCompare(envelope[0:4], EnvelopeMagic) != 1 {
		return nil, nil, ErrIntegrityCheckFailed
	}
	if envelope[4] != EnvelopeVersion {
		return nil, nil, ErrIntegrityCheckFailed
	}

	headerLen := int(binary.BigEndian.Uint32(envelope[5:9]))
	if headerLen <= 0 || headerLen > MaxHeaderLength {
		return nil, nil, ErrIntegrityCheckFailed
	}
	if len(envelope) < 9+headerLen+32 {
		return nil, nil, ErrIntegrityCheckFailed
	}

	headerJSON := envelope[9 : 9+headerLen]
	ciphertext := envelope[9+headerLen : len(envelope)-32]
	tag := envelope[len(envelope)-32:]

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}

	// Validate authenticated context against caller expected context
	if header.PayloadID != ctx.PayloadID ||
		header.OwnerID != ctx.OwnerID ||
		header.ContentRevision != ctx.ContentRevision ||
		header.VariantID != ctx.VariantID {
		return nil, nil, ErrIntegrityCheckFailed
	}
	if ctx.FileID == nil && header.FileID != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}
	if ctx.FileID != nil && (header.FileID == nil || *header.FileID != *ctx.FileID) {
		return nil, nil, ErrIntegrityCheckFailed
	}

	rootKey, err := keyProvider.GetRootKey(header.RootKeyID)
	if err != nil || len(rootKey) != 32 {
		return nil, nil, ErrIntegrityCheckFailed
	}

	salt, err := base64.StdEncoding.DecodeString(header.Salt)
	if err != nil || len(salt) != 32 {
		return nil, nil, ErrIntegrityCheckFailed
	}

	spec, err := GetVariant(header.VariantID)
	if err != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}

	// Derive MAC key
	kdfStart := time.Now()
	macInfo := buildHKDFInfo(1, header.PayloadID, header.OwnerID, header.FileID, header.ContentRevision, header.VariantID, "mac")
	macKey, err := deriveKey(rootKey, salt, macInfo, 32)
	if err != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}
	timings.KDFDuration = time.Since(kdfStart)

	// Verify MAC tag
	macStart := time.Now()
	macData := envelope[:len(envelope)-32]
	h := hmac.New(sha256.New, macKey)
	h.Write(macData)
	computedTag := h.Sum(nil)
	if subtle.ConstantTimeCompare(tag, computedTag) != 1 {
		return nil, nil, ErrIntegrityCheckFailed
	}
	timings.MACVerifyDuration = time.Since(macStart)

	// Derive enc key
	kdf2Start := time.Now()
	encInfo := buildHKDFInfo(1, header.PayloadID, header.OwnerID, header.FileID, header.ContentRevision, header.VariantID, "enc")
	encKey, err := deriveKey(rootKey, salt, encInfo, spec.KeyBytes)
	if err != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}
	timings.KDFDuration += time.Since(kdf2Start)

	var iv []byte
	if spec.IVBytes > 0 {
		iv, err = base64.StdEncoding.DecodeString(header.IV)
		if err != nil || len(iv) != spec.IVBytes {
			return nil, nil, ErrIntegrityCheckFailed
		}
	}

	// Decrypt
	cipherStart := time.Now()
	plaintext, err := decryptCiphertext(spec, encKey, iv, ciphertext)
	if err != nil {
		return nil, nil, ErrIntegrityCheckFailed
	}
	timings.DecryptCipherDuration = time.Since(cipherStart)

	if int64(len(plaintext)) != header.PlaintextBytes {
		return nil, nil, ErrIntegrityCheckFailed
	}

	timings.OpenTotalDuration = time.Since(totalStart)
	return plaintext, timings, nil
}

func encryptPlaintext(spec VariantSpec, key, iv, plaintext []byte) ([]byte, error) {
	switch spec.Algorithm {
	case AlgoAES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch spec.Mode {
		case ModeCBC:
			padded, err := PKCS7Pad(plaintext, aes.BlockSize)
			if err != nil {
				return nil, err
			}
			ciphertext := make([]byte, len(padded))
			mode := cipher.NewCBCEncrypter(block, iv)
			mode.CryptBlocks(ciphertext, padded)
			return ciphertext, nil
		case ModeCFB128:
			ciphertext := make([]byte, len(plaintext))
			stream := cipher.NewCFBEncrypter(block, iv)
			stream.XORKeyStream(ciphertext, plaintext)
			return ciphertext, nil
		case ModeOFB:
			ciphertext := make([]byte, len(plaintext))
			stream := cipher.NewOFB(block, iv)
			stream.XORKeyStream(ciphertext, plaintext)
			return ciphertext, nil
		case ModeCTR:
			ciphertext := make([]byte, len(plaintext))
			stream := cipher.NewCTR(block, iv)
			stream.XORKeyStream(ciphertext, plaintext)
			return ciphertext, nil
		default:
			return nil, fmt.Errorf("unsupported AES mode: %s", spec.Mode)
		}

	case AlgoDES:
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		padded, err := PKCS7Pad(plaintext, des.BlockSize)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, len(padded))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, padded)
		return ciphertext, nil

	case AlgoRC4:
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, len(plaintext))
		c.XORKeyStream(ciphertext, plaintext)
		return ciphertext, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", spec.Algorithm)
	}
}

func decryptCiphertext(spec VariantSpec, key, iv, ciphertext []byte) ([]byte, error) {
	switch spec.Algorithm {
	case AlgoAES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch spec.Mode {
		case ModeCBC:
			if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
				return nil, ErrIntegrityCheckFailed
			}
			padded := make([]byte, len(ciphertext))
			mode := cipher.NewCBCDecrypter(block, iv)
			mode.CryptBlocks(padded, ciphertext)
			plaintext, err := PKCS7Unpad(padded, aes.BlockSize)
			if err != nil {
				return nil, ErrIntegrityCheckFailed
			}
			return plaintext, nil
		case ModeCFB128:
			plaintext := make([]byte, len(ciphertext))
			stream := cipher.NewCFBDecrypter(block, iv)
			stream.XORKeyStream(plaintext, ciphertext)
			return plaintext, nil
		case ModeOFB:
			plaintext := make([]byte, len(ciphertext))
			stream := cipher.NewOFB(block, iv)
			stream.XORKeyStream(plaintext, ciphertext)
			return plaintext, nil
		case ModeCTR:
			plaintext := make([]byte, len(ciphertext))
			stream := cipher.NewCTR(block, iv)
			stream.XORKeyStream(plaintext, ciphertext)
			return plaintext, nil
		default:
			return nil, fmt.Errorf("unsupported AES mode: %s", spec.Mode)
		}

	case AlgoDES:
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(ciphertext) == 0 || len(ciphertext)%des.BlockSize != 0 {
			return nil, ErrIntegrityCheckFailed
		}
		padded := make([]byte, len(ciphertext))
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(padded, ciphertext)
		plaintext, err := PKCS7Unpad(padded, des.BlockSize)
		if err != nil {
			return nil, ErrIntegrityCheckFailed
		}
		return plaintext, nil

	case AlgoRC4:
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		plaintext := make([]byte, len(ciphertext))
		c.XORKeyStream(plaintext, ciphertext)
		return plaintext, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", spec.Algorithm)
	}
}

