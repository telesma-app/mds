package mdsverify

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDefaultTrustAnchorIsGlobalSignR46(t *testing.T) {
	anchors, err := DefaultTrustAnchors()
	if err != nil {
		t.Fatalf("DefaultTrustAnchors: %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("default trust anchors = %d, want 1", len(anchors))
	}

	fingerprint := sha256.Sum256(anchors[0].Raw)
	const want = "4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9"
	if got := hex.EncodeToString(fingerprint[:]); got != want {
		t.Fatalf("default trust anchor fingerprint = %s, want %s", got, want)
	}
}
