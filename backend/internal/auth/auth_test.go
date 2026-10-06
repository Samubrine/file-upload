package auth

import (
	"bytes"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	password := "correct horse battery staple 123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	match, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Errorf("expected password to match")
	}

	wrongMatch, err := VerifyPassword("wrong password here", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed on wrong password: %v", err)
	}
	if wrongMatch {
		t.Errorf("expected wrong password not to match")
	}
}

func TestIdentityNormalizationAndLookup(t *testing.T) {
	key := []byte("01234567890123456789012345678901")

	u1 := "Alice_Wonder"
	u2 := "  alice_wonder  "
	if NormalizeUsername(u1) != "alice_wonder" {
		t.Errorf("normalization failed")
	}
	l1 := ComputeUsernameLookup(key, u1)
	l2 := ComputeUsernameLookup(key, u2)
	if !bytes.Equal(l1, l2) {
		t.Errorf("expected normalized usernames to produce identical lookup tokens")
	}

	e1 := "Alice@Example.COM"
	e2 := "alice@example.com  "
	el1 := ComputeEmailLookup(key, e1)
	el2 := ComputeEmailLookup(key, e2)
	if !bytes.Equal(el1, el2) {
		t.Errorf("expected normalized emails to produce identical lookup tokens")
	}
}

func TestCSRFValidation(t *testing.T) {
	raw, hash, err := GenerateRandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateCSRF(raw, hash) {
		t.Errorf("expected valid CSRF to pass")
	}
	if ValidateCSRF("bad-csrf-token", hash) {
		t.Errorf("expected bad CSRF to fail")
	}
}

