package internal

import (
	"os"
	"testing"
)

// TestVerifyAndParse_RealBlob exercises the full verify+parse path against a real
// FIDO Alliance MDS blob captured to a file. It is skipped unless
// FIDO_BLOB_FIXTURE points at that file, so CI/offline runs don't depend on the
// network or a checked-in multi-MB blob.
//
//	curl -s https://mds.fidoalliance.org/ -o /tmp/mds-blob.jwt
//	FIDO_BLOB_FIXTURE=/tmp/mds-blob.jwt go test ./services/fido-service/internal -run RealBlob -v
func TestVerifyAndParse_RealBlob(t *testing.T) {
	path := os.Getenv("FIDO_BLOB_FIXTURE")
	if path == "" {
		t.Skip("set FIDO_BLOB_FIXTURE to a captured MDS blob to run this test")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	f, err := NewFetcher("", "")
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	payload, err := f.VerifyAndParse(raw)
	if err != nil {
		t.Fatalf("VerifyAndParse: %v", err)
	}
	if payload.Number == 0 || len(payload.Entries) == 0 {
		t.Fatalf("parsed empty blob: number=%d entries=%d", payload.Number, len(payload.Entries))
	}

	idx := buildIndex(payload, SnapshotMeta{Number: payload.Number, Source: "fixture"})
	if idx.count() == 0 {
		t.Fatalf("index is empty after build")
	}

	// A well-known hardware key should be present and classified hardware-bound.
	if p, ok := idx.lookup("ee882879-721c-4913-9775-3dfcce97072a"); ok {
		t.Logf("YubiKey 5 NFC: binding=%s cert=%s prf=%v largeBlob=%v tier=%s",
			p.Binding, p.Certification.Status, p.Extensions.PRF, p.Extensions.LargeBlob, p.RiskTier)
	}
	t.Logf("parsed blob no=%d entries=%d indexed=%d", payload.Number, len(payload.Entries), idx.count())
}
