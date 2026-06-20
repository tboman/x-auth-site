package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

func toBase64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func testSigner(t *testing.T) *jwtx.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jwtx.NewSigner(key)
}

// managerWithFixture builds a manager whose trust store anchors the fixture root,
// and rewrites a created verification's binding material to match the fixture so
// the prebuilt DeviceResponse verifies.
func managerWithFixture(t *testing.T, fx fixtureKit, signer *jwtx.Signer) *Manager {
	t.Helper()
	ts := strictTrust(t, fx.rootPEM)
	store := NewMemStorage()
	return NewManager(store, ts, signer, nil, "https://id.test", time.Minute, testLogger())
}

func TestSubmitResponse_Verified(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	signer := testSigner(t)
	mgr := managerWithFixture(t, fx, signer)
	ctx := context.Background()

	v, err := mgr.CreateVerification(ctx, "ten_demo", VerifyRequestSpec{Purpose: "wire"})
	if err != nil {
		t.Fatal(err)
	}
	// Align the stored binding material with the fixture's transcript inputs.
	v.ClientID = fx.clientID
	v.ResponseURI = fx.responseURI
	v.Nonce = fx.nonce
	if err := mgr.store.Update(ctx, v); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(string(toBase64URL(fx.response)))
	out, err := mgr.SubmitResponse(ctx, v.ID, ResponseSubmission{
		VPToken:            body,
		MDocGeneratedNonce: fx.mdocNonce,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.Status != StatusVerified {
		t.Fatalf("status = %q, want verified (result=%+v)", out.Status, out.Result)
	}
	if out.Result.Assurance != AssuranceHigh {
		t.Errorf("assurance = %q, want high", out.Result.Assurance)
	}
	if out.Result.Claims["given_name"] != "Erika" {
		t.Errorf("given_name = %v", out.Result.Claims["given_name"])
	}
	if out.Result.ProofToken == "" {
		t.Error("expected a signed proof token")
	}
	// Proof token verifies against the signer's published JWKS.
	ver, err := jwtx.NewVerifierFromJWKS("https://id.test", signer.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ver.Verify(out.Result.ProofToken, time.Now()); err != nil {
		t.Errorf("proof token did not verify: %v", err)
	}
}

func TestSubmitResponse_BadTokenFails(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	mgr := managerWithFixture(t, fx, testSigner(t))
	ctx := context.Background()

	v, err := mgr.CreateVerification(ctx, "ten_demo", VerifyRequestSpec{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal("not-valid-base64-mdoc!!")
	out, err := mgr.SubmitResponse(ctx, v.ID, ResponseSubmission{VPToken: body})
	if err != nil {
		t.Fatalf("submit returned error (should record failure): %v", err)
	}
	if out.Status != StatusFailed {
		t.Errorf("status = %q, want failed", out.Status)
	}
}

func TestSubmitResponse_Expired(t *testing.T) {
	fx := buildFixture(t, defaultClaims())
	mgr := managerWithFixture(t, fx, testSigner(t))
	ctx := context.Background()

	v, err := mgr.CreateVerification(ctx, "ten_demo", VerifyRequestSpec{})
	if err != nil {
		t.Fatal(err)
	}
	v.ExpiresAt = time.Now().Add(-time.Minute)
	_ = mgr.store.Update(ctx, v)

	body, _ := json.Marshal(string(toBase64URL(fx.response)))
	if _, err := mgr.SubmitResponse(ctx, v.ID, ResponseSubmission{VPToken: body}); err != errExpired {
		t.Fatalf("err = %v, want errExpired", err)
	}
}

func TestGet_TenantScoped(t *testing.T) {
	mgr := NewManager(NewMemStorage(), mustInsecureTrust(t), testSigner(t), nil, "https://id.test", time.Minute, testLogger())
	ctx := context.Background()
	v, _ := mgr.CreateVerification(ctx, "ten_a", VerifyRequestSpec{})
	if _, err := mgr.Get(ctx, "ten_b", v.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant read err = %v, want ErrNotFound", err)
	}
	if _, err := mgr.Get(ctx, "ten_a", v.ID); err != nil {
		t.Fatalf("same-tenant read err = %v", err)
	}
}

func mustInsecureTrust(t *testing.T) *TrustStore {
	t.Helper()
	ts, err := NewTrustStore(TrustModeInsecure, "", "", testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return ts
}
