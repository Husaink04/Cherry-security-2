package agent

import (
	"bytes"
	"testing"
)

func TestCurrentUserDPAPIRoundtrip(t *testing.T) {
	original := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	blob, err := ProtectCredential(original)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, original) {
		t.Fatal("plaintext secret in protected blob")
	}
	plain, err := UnprotectCredential(blob)
	if err != nil || !bytes.Equal(plain, original) {
		t.Fatal("DPAPI roundtrip failed")
	}
	blob[len(blob)/2] ^= 1
	if _, err = UnprotectCredential(blob); err == nil {
		t.Fatal("corrupt credential accepted")
	}
}
