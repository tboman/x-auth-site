package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

func riskDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// riskCAEPSigner stands in for authentication-service's signing key.
var riskCAEPSigner = func() *jwtx.Signer {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return jwtx.NewSigner(key)
}()

func signSET(t *testing.T, claims jwtx.Claims, eventURI string, payload map[string]any) string {
	t.Helper()
	set, err := riskCAEPSigner.Sign(claims, map[string]any{"events": map[string]any{eventURI: payload}})
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return set
}

func newReceiver(t *testing.T) *Handlers {
	t.Helper()
	v, err := jwtx.NewVerifierFromJWKS("http://authn.test", riskCAEPSigner.JWKS())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return &Handlers{Store: NewMemStorage(), Logger: riskDiscard(), Clock: SystemClock{}, CAEPVerifier: v}
}

func setClaims() jwtx.Claims {
	now := time.Now().UTC()
	return jwtx.Claims{
		Iss: "http://authn.test", Sub: "u1", TenantID: "ten_a", SessionID: "s1",
		Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(), JTI: "set_" + uuidish(),
	}
}

func uuidish() string { return time.Now().Format("150405.000000000") }

func TestCAEPReceiverAppliesAssurance(t *testing.T) {
	h := newReceiver(t)
	set := signSET(t, setClaims(), CAEPAssuranceLevelChange,
		map[string]any{"current_level": "nist-aal2", "change_direction": "increase"})

	w := httptest.NewRecorder()
	h.ReceiveSET(w, httptest.NewRequest(http.MethodPost, "/internal/v1/ssf/events", strings.NewReader(set)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", w.Code, w.Body.String())
	}
	as, err := h.Store.GetAssurance("ten_a", "u1")
	if err != nil || as.Level != "nist-aal2" || !as.Compliant {
		t.Fatalf("assurance not applied: %+v err=%v", as, err)
	}
}

// An assurance-level-change SET carrying a transaction_id stores a transaction
// completion (and one without it does not).
func TestCAEPReceiverStoresTransactionCompletion(t *testing.T) {
	h := newReceiver(t)
	set := signSET(t, setClaims(), CAEPAssuranceLevelChange, map[string]any{
		"current_level":  "urn:xauth:protect:ultra:strict",
		"transaction_id": "txn_abc",
		"acr":            "urn:xauth:protect:ultra:strict",
		"rank":           8,
	})
	w := httptest.NewRecorder()
	h.ReceiveSET(w, httptest.NewRequest(http.MethodPost, "/internal/v1/ssf/events", strings.NewReader(set)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", w.Code, w.Body.String())
	}
	tc, err := h.Store.GetTransactionCompletion("ten_a", "txn_abc")
	if err != nil {
		t.Fatalf("completion not stored: %v", err)
	}
	if tc.UserID != "u1" || tc.ACR != "urn:xauth:protect:ultra:strict" || tc.Rank != 8 {
		t.Fatalf("completion wrong: %+v", tc)
	}

	// A plain assurance event (no transaction_id) must not create a completion.
	set2 := signSET(t, setClaims(), CAEPAssuranceLevelChange, map[string]any{"current_level": "nist-aal2"})
	w2 := httptest.NewRecorder()
	h.ReceiveSET(w2, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(set2)))
	if _, err := h.Store.GetTransactionCompletion("ten_a", "no-such"); err != ErrNotFound {
		t.Errorf("non-transaction event should not store a completion")
	}
}

func TestTransactionCompletionStorageMem(t *testing.T) {
	s := NewMemStorage()
	tc := TransactionCompletion{TransactionID: "txn_1", TenantID: "ten_a", UserID: "u1",
		ACR: "urn:xauth:protect:high:strict", Rank: 4, CompletedAt: time.Now().UTC()}
	if err := s.RecordTransactionCompletion(tc); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := s.GetTransactionCompletion("ten_a", "txn_1")
	if err != nil || got.Rank != 4 || got.UserID != "u1" {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := s.GetTransactionCompletion("ten_b", "txn_1"); err != ErrNotFound {
		t.Errorf("cross-tenant read should be ErrNotFound")
	}
	if _, err := s.GetTransactionCompletion("ten_a", "txn_x"); err != ErrNotFound {
		t.Errorf("missing read should be ErrNotFound")
	}
}

func TestCAEPReceiverRejectsInvalid(t *testing.T) {
	h := newReceiver(t)
	w := httptest.NewRecorder()
	h.ReceiveSET(w, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not-a-jwt")))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("garbage SET: want 401, got %d", w.Code)
	}

	// Unconfigured receiver → 503.
	h2 := &Handlers{Store: NewMemStorage(), Logger: riskDiscard(), Clock: SystemClock{}}
	w2 := httptest.NewRecorder()
	h2.ReceiveSET(w2, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("anything")))
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured: want 503, got %d", w2.Code)
	}
}

func TestCAEPReceiverComplianceAndRevoke(t *testing.T) {
	h := newReceiver(t)

	// device-compliance-change → non-compliant.
	set := signSET(t, setClaims(), CAEPDeviceComplianceChange, map[string]any{"current_status": "not-compliant"})
	w := httptest.NewRecorder()
	h.ReceiveSET(w, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(set)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("compliance: want 202, got %d", w.Code)
	}
	if as, _ := h.Store.GetAssurance("ten_a", "u1"); as.Compliant {
		t.Fatalf("should be non-compliant: %+v", as)
	}

	// session-revoked → accepted (recorded; risk-service doesn't own sessions).
	set2 := signSET(t, setClaims(), CAEPSessionRevoked, map[string]any{"reason_admin": "replay"})
	w2 := httptest.NewRecorder()
	h.ReceiveSET(w2, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(set2)))
	if w2.Code != http.StatusAccepted {
		t.Fatalf("revoke: want 202, got %d", w2.Code)
	}
}
