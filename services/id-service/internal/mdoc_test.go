package internal

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func strictTrust(t *testing.T, rootPEM []byte) *TrustStore {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/root.pem"
	if err := os.WriteFile(path, rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := NewTrustStore(TrustModeStrict, path, "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func params(fx fixtureKit) verifyParams {
	return verifyParams{
		docType:     DefaultDocType,
		clientID:    fx.clientID,
		responseURI: fx.responseURI,
		nonce:       fx.nonce,
		mdocNonce:   fx.mdocNonce,
		now:         time.Now(),
	}
}

func TestVerifyDeviceResponse_TrustedAndDeviceBound(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	ts := strictTrust(t, fx.rootPEM)

	out, err := verifyDeviceResponse(fx.response, ts, params(fx))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !out.issuerTrusted {
		t.Error("expected issuer trusted under strict mode with the right root")
	}
	if !out.deviceBound {
		t.Error("expected device-bound (valid device signature)")
	}
	if out.claims["family_name"] != "Mustermann" {
		t.Errorf("family_name = %v", out.claims["family_name"])
	}
	if out.claims["age_over_21"] != true {
		t.Errorf("age_over_21 = %v", out.claims["age_over_21"])
	}
	if a, _ := deriveAssurance(out); a != AssuranceHigh {
		t.Errorf("assurance = %q, want high", a)
	}
}

func TestVerifyDeviceResponse_UntrustedRootStrictFails(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	// A strict store with NO roots cannot anchor the issuer chain.
	ts, err := NewTrustStore(TrustModeStrict, "", "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDeviceResponse(fx.response, ts, params(fx)); err == nil {
		t.Fatal("expected strict verification to fail with no trusted root")
	}
}

func TestVerifyDeviceResponse_InsecureAcceptsUntrusted(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	ts, err := NewTrustStore(TrustModeInsecure, "", "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	out, err := verifyDeviceResponse(fx.response, ts, params(fx))
	if err != nil {
		t.Fatalf("insecure verify: %v", err)
	}
	if out.issuerTrusted {
		t.Error("issuer should be flagged untrusted in insecure mode without a root")
	}
	if !out.deviceBound {
		t.Error("device binding should still verify")
	}
	if a, _ := deriveAssurance(out); a != AssuranceMedium {
		t.Errorf("assurance = %q, want medium (device-bound, untrusted issuer)", a)
	}
}

func TestVerifyDeviceResponse_WrongNonceFailsDeviceBinding(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	ts := strictTrust(t, fx.rootPEM)
	p := params(fx)
	p.nonce = "a-different-nonce" // breaks the session transcript binding
	if _, err := verifyDeviceResponse(fx.response, ts, p); err == nil {
		t.Fatal("expected device-signature verification to fail with a mismatched nonce")
	}
}

func TestVerifyDeviceResponse_TamperedResponseFails(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	ts := strictTrust(t, fx.rootPEM)

	// Flip a byte in the middle of the response; any of the signature/digest
	// checks must reject it.
	tampered := bytes.Clone(fx.response)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := verifyDeviceResponse(tampered, ts, params(fx)); err == nil {
		t.Fatal("expected verification of a tampered response to fail")
	}
}
