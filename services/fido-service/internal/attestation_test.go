package internal

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// makeAttestationObject builds a minimal "none"-format attestation object whose
// authenticator data carries the given flags and no attested credential data
// (37-byte authData), CBOR-encoded and base64url-wrapped.
func makeAttestationObject(t *testing.T, flags byte) string {
	t.Helper()
	authData := make([]byte, 37) // 32 rpIdHash + 1 flags + 4 counter
	authData[32] = flags
	raw, err := webauthncbor.Marshal(map[string]interface{}{
		"authData": authData,
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseAttestation_Flags(t *testing.T) {
	const flagUP, flagUV, flagBE, flagBS = 1, 4, 8, 16
	obj := makeAttestationObject(t, flagUP|flagUV|flagBE|flagBS)

	aaguid, flags, err := parseAttestation(AttestationRequest{AttestationObject: obj})
	if err != nil {
		t.Fatalf("parseAttestation: %v", err)
	}
	if aaguid != "" {
		t.Fatalf("aaguid=%q, want empty (no attested credential data)", aaguid)
	}
	if !flags.UserPresent || !flags.UserVerified || !flags.BackupEligible || !flags.BackupState {
		t.Fatalf("flags=%+v, want all of UP/UV/BE/BS set", flags)
	}
	if flags.AttestedCredentialData {
		t.Fatalf("did not expect AT flag")
	}
}

func TestParseAttestation_Empty(t *testing.T) {
	_, _, err := parseAttestation(AttestationRequest{})
	if !errors.Is(err, errNoAttestation) {
		t.Fatalf("err=%v, want errNoAttestation", err)
	}
}

func TestDecodeBase64_Alphabets(t *testing.T) {
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xFF}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		got, err := decodeBase64(enc.EncodeToString(want))
		if err != nil {
			t.Fatalf("decode %v: %v", enc, err)
		}
		if string(got) != string(want) {
			t.Fatalf("round trip mismatch: got %x want %x", got, want)
		}
	}
}
