package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

// forgeEnvelope builds an envelope with a correct MAC over an arbitrary header,
// so only the header parser can reject it.
func forgeEnvelope(t *testing.T, rootKey []byte, ctx Context, header func(salt, iv string) string, plaintext []byte) []byte {
	t.Helper()
	spec, err := GetVariant(ctx.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatal(err)
	}
	encKey, err := deriveKey(rootKey, salt, buildHKDFInfo(1, ctx.PayloadID, ctx.OwnerID, ctx.FileID, ctx.ContentRevision, ctx.VariantID, "enc"), spec.KeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := deriveKey(rootKey, salt, buildHKDFInfo(1, ctx.PayloadID, ctx.OwnerID, ctx.FileID, ctx.ContentRevision, ctx.VariantID, "mac"), 32)
	if err != nil {
		t.Fatal(err)
	}
	var iv []byte
	ivB64 := ""
	if spec.IVBytes > 0 {
		iv = make([]byte, spec.IVBytes)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			t.Fatal(err)
		}
		ivB64 = base64.StdEncoding.EncodeToString(iv)
	}
	ct, err := encryptPlaintext(spec, encKey, iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	h := []byte(header(base64.StdEncoding.EncodeToString(salt), ivB64))
	var buf bytes.Buffer
	buf.Write(EnvelopeMagic)
	buf.WriteByte(EnvelopeVersion)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(h)))
	buf.Write(h)
	buf.Write(ct)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(buf.Bytes())
	buf.Write(mac.Sum(nil))
	return buf.Bytes()
}

// V13: unknown and duplicate header fields are refused even with a valid MAC.
func TestV13StrictHeaderParser(t *testing.T) {
	rootKey := bytes.Repeat([]byte{7}, 32)
	kp := NewMemoryKeyProvider(map[string][]byte{"root-1": rootKey})
	ctx := Context{PayloadID: "p", OwnerID: "o", ContentRevision: 1, VariantID: VariantAES256CTR}
	pt := []byte("forged payload")
	base := func(extra string) func(string, string) string {
		return func(salt, iv string) string {
			return fmt.Sprintf(`{"payload_id":"p","owner_id":"o","file_id":null,"content_revision":1,"variant_id":"aes-256-ctr","root_key_id":"root-1","salt":"%s","iv":"%s","plaintext_bytes":%d%s}`, salt, iv, len(pt), extra)
		}
	}

	if _, _, err := Open(ctx, kp, forgeEnvelope(t, rootKey, ctx, base(""), pt)); err != nil {
		t.Fatalf("control envelope should open: %v", err)
	}
	if _, _, err := Open(ctx, kp, forgeEnvelope(t, rootKey, ctx, base(`,"role":"admin"`), pt)); err != ErrIntegrityCheckFailed {
		t.Fatalf("unknown header field accepted: %v", err)
	}
	if _, _, err := Open(ctx, kp, forgeEnvelope(t, rootKey, ctx, base(`,"variant_id":"aes-256-ctr"`), pt)); err != ErrIntegrityCheckFailed {
		t.Fatalf("duplicate header key accepted: %v", err)
	}
}
