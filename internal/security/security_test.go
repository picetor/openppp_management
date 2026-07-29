package security

import "testing"

func TestGUIDRoundTrip(t *testing.T) {
	guid, err := NewGUID()
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := NormalizeGUID(guid)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != guid {
		t.Fatalf("expected %s, got %s", guid, normalized)
	}
}

func TestNormalizeGUIDRejectsInvalidValue(t *testing.T) {
	if _, err := NormalizeGUID("not-a-guid"); err == nil {
		t.Fatal("expected invalid GUID to be rejected")
	}
}

func TestPasswordHash(t *testing.T) {
	hash, err := HashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "a-long-test-password") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password must not verify")
	}
}
