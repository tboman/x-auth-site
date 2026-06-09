package jwtx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/logx"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func sampleClaims(now time.Time) Claims {
	return Claims{
		Sub:       "usr_1",
		Iss:       "https://auth.x-auth.test",
		Aud:       "cli_default",
		Exp:       now.Add(time.Hour).Unix(),
		Iat:       now.Unix(),
		TenantID:  "ten_a",
		Scope:     "openid profile",
		SessionID: "ses_1",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	signer := NewSigner(key)

	tok, err := signer.Sign(sampleClaims(now), map[string]any{"install_id": "ins_9"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if parts := strings.Split(tok, "."); len(parts) != 3 {
		t.Fatalf("want compact JWS with 3 parts, got %d", len(parts))
	}

	v := NewVerifier("https://auth.x-auth.test", &key.PublicKey)
	claims, raw, err := v.Verify(tok, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != "usr_1" || claims.TenantID != "ten_a" || claims.SessionID != "ses_1" {
		t.Fatalf("claims did not round-trip: %+v", claims)
	}
	if raw["install_id"] != "ins_9" {
		t.Fatalf("extra claim lost: %v", raw)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	tok, err := NewSigner(key).Sign(sampleClaims(now), nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.Split(tok, ".")
	var payload map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(raw, &payload)
	payload["tenant_id"] = "ten_evil"
	forged, _ := json.Marshal(payload)
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	v := NewVerifier("", &key.PublicKey)
	if _, _, err := v.Verify(strings.Join(parts, "."), now); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature for tampered payload, got %v", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	now := time.Now().UTC()
	signKey := testKey(t)
	otherKey := testKey(t)
	tok, _ := NewSigner(signKey).Sign(sampleClaims(now), nil)

	v := NewVerifier("", &otherKey.PublicKey)
	if _, _, err := v.Verify(tok, now); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey (kid mismatch), got %v", err)
	}
}

func TestVerifyTimeWindow(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	signer := NewSigner(key)
	v := NewVerifier("", &key.PublicKey)

	expired := sampleClaims(now)
	expired.Exp = now.Add(-time.Hour).Unix()
	tok, _ := signer.Sign(expired, nil)
	if _, _, err := v.Verify(tok, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	// Within leeway: a token expired 10s ago still verifies.
	graceful := sampleClaims(now)
	graceful.Exp = now.Add(-10 * time.Second).Unix()
	tok, _ = signer.Sign(graceful, nil)
	if _, _, err := v.Verify(tok, now); err != nil {
		t.Fatalf("token within leeway must verify, got %v", err)
	}

	future := sampleClaims(now)
	future.Iat = now.Add(time.Hour).Unix()
	tok, _ = signer.Sign(future, nil)
	if _, _, err := v.Verify(tok, now); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}
}

func TestVerifyIssuer(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	tok, _ := NewSigner(key).Sign(sampleClaims(now), nil)

	v := NewVerifier("https://other.issuer", &key.PublicKey)
	if _, _, err := v.Verify(tok, now); !errors.Is(err, ErrIssuer) {
		t.Fatalf("want ErrIssuer, got %v", err)
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	kid := KeyID(&key.PublicKey)

	// Hand-build an alg:none token reusing a known kid — must be rejected on
	// algorithm before any signature logic runs.
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`))
	payload, _ := json.Marshal(sampleClaims(now))
	p := base64.RawURLEncoding.EncodeToString(payload)
	tok := h + "." + p + "."

	v := NewVerifier("", &key.PublicKey)
	if _, _, err := v.Verify(tok, now); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("want ErrAlgorithm for alg:none, got %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	v := NewVerifier("", &testKey(t).PublicKey)
	for _, tok := range []string{"", "abc", "a.b", "a.b.c.d", "!!!.???.###"} {
		if _, _, err := v.Verify(tok, time.Now()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: want ErrMalformed, got %v", tok, err)
		}
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	key := testKey(t)
	signer := NewSigner(key)
	tok, _ := signer.Sign(sampleClaims(now), nil)

	// Serve → parse → verify, as a sister service would.
	served, err := json.Marshal(signer.JWKS())
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	var parsed JWKS
	if err := json.Unmarshal(served, &parsed); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	v, err := NewVerifierFromJWKS("https://auth.x-auth.test", parsed)
	if err != nil {
		t.Fatalf("verifier from jwks: %v", err)
	}
	if _, _, err := v.Verify(tok, now); err != nil {
		t.Fatalf("verify via jwks-derived key: %v", err)
	}

	jwk := parsed.Keys[0]
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" || jwk.Kid != signer.KID() {
		t.Fatalf("unexpected jwk metadata: %+v", jwk)
	}
}

func TestVerifierSupportsRotation(t *testing.T) {
	now := time.Now().UTC()
	oldKey := testKey(t)
	newKey := testKey(t)
	oldTok, _ := NewSigner(oldKey).Sign(sampleClaims(now), nil)
	newTok, _ := NewSigner(newKey).Sign(sampleClaims(now), nil)

	v := NewVerifier("", &oldKey.PublicKey, &newKey.PublicKey)
	if _, _, err := v.Verify(oldTok, now); err != nil {
		t.Fatalf("old key token must verify during rotation: %v", err)
	}
	if _, _, err := v.Verify(newTok, now); err != nil {
		t.Fatalf("new key token must verify: %v", err)
	}
}

func TestExtraClaimCollision(t *testing.T) {
	signer := NewSigner(testKey(t))
	_, err := signer.Sign(sampleClaims(time.Now()), map[string]any{"sub": "spoofed"})
	if err == nil {
		t.Fatal("colliding extra claim must be rejected")
	}
}

func TestLoadOrGenerateKey(t *testing.T) {
	logger := logx.New("jwtx-test")

	// Unset env: generates an ephemeral key.
	t.Setenv("JWTX_TEST_KEY", "")
	key, err := LoadOrGenerateKey("JWTX_TEST_KEY", logger)
	if err != nil || key == nil {
		t.Fatalf("ephemeral generation failed: %v", err)
	}

	// PKCS#1 PEM round-trip via env.
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	t.Setenv("JWTX_TEST_KEY", string(pemBytes))
	loaded, err := LoadOrGenerateKey("JWTX_TEST_KEY", logger)
	if err != nil {
		t.Fatalf("load PKCS#1: %v", err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded key differs from encoded key")
	}

	// PKCS#8 PEM.
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	t.Setenv("JWTX_TEST_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})))
	if _, err := LoadOrGenerateKey("JWTX_TEST_KEY", logger); err != nil {
		t.Fatalf("load PKCS#8: %v", err)
	}

	// Garbage PEM errors out rather than silently generating.
	t.Setenv("JWTX_TEST_KEY", "not a pem")
	if _, err := LoadOrGenerateKey("JWTX_TEST_KEY", logger); err == nil {
		t.Fatal("garbage key material must error, not fall back")
	}
}
