package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func adviceTestSetup(t *testing.T) (*AdviceHandlers, string, string) {
	t.Helper()
	store := NewMemStorage()
	const clientID, secret, tenant = "cli_acme", "s3cr3t", "ten_acme"
	if err := store.PutClient(OIDCClient{
		ClientID: clientID, TenantID: tenant, ClientSecretHash: HashToken(secret), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("put client: %v", err)
	}
	if err := store.CreateTransactionType(TransactionType{
		TenantID: tenant, Name: "payment.high", ACR: "urn:xauth:protect:ultra:strict", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create txn type: %v", err)
	}
	return &AdviceHandlers{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, clientID, secret
}

func adviceReq(body, user, pass string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/advice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	return req
}

func TestAdviceMapsTransactionTypeToLevel(t *testing.T) {
	h, clientID, secret := adviceTestSetup(t)
	w := httptest.NewRecorder()
	h.Advise(w, adviceReq(`{"session_id":"ses_1","user_id":"usr_1","device_id":"dev_1","transaction_type":"payment.high"}`, clientID, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		TenantID string `json:"tenant_id"`
		Advice   struct {
			ACR  string `json:"acr"`
			Rank int    `json:"rank"`
			Band string `json:"band"`
			Name string `json:"name"`
		} `json:"advice"`
		Subject struct {
			UserID string `json:"user_id"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != "ten_acme" || resp.Advice.ACR != "urn:xauth:protect:ultra:strict" ||
		resp.Advice.Rank != 8 || resp.Advice.Band != "ultra" || resp.Advice.Name != "strict" {
		t.Fatalf("bad advice: %+v", resp)
	}
	if resp.Subject.UserID != "usr_1" {
		t.Errorf("subject not echoed: %+v", resp.Subject)
	}
}

func TestAdviceUnknownType404(t *testing.T) {
	h, clientID, secret := adviceTestSetup(t)
	w := httptest.NewRecorder()
	h.Advise(w, adviceReq(`{"transaction_type":"nope"}`, clientID, secret))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestAdviceRequiresConfidentialClient(t *testing.T) {
	h, clientID, _ := adviceTestSetup(t)
	for name, req := range map[string]*http.Request{
		"no auth":     adviceReq(`{"transaction_type":"payment.high"}`, "", ""),
		"wrong secret": adviceReq(`{"transaction_type":"payment.high"}`, clientID, "wrong"),
		"unknown client": adviceReq(`{"transaction_type":"payment.high"}`, "cli_nope", "x"),
	} {
		w := httptest.NewRecorder()
		h.Advise(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d", name, w.Code)
		}
	}
}

func TestAdvicePublicClientRejected(t *testing.T) {
	store := NewMemStorage()
	_ = store.PutClient(OIDCClient{ClientID: "cli_pub", TenantID: "ten_x", CreatedAt: time.Now().UTC()}) // no secret hash
	_ = store.CreateTransactionType(TransactionType{TenantID: "ten_x", Name: "login", ACR: "urn:xauth:protect:high:protected", CreatedAt: time.Now().UTC()})
	h := &AdviceHandlers{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := httptest.NewRecorder()
	h.Advise(w, adviceReq(`{"transaction_type":"login"}`, "cli_pub", "anything"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("public client: want 401, got %d", w.Code)
	}
}

func TestAdviceMissingType400(t *testing.T) {
	h, clientID, secret := adviceTestSetup(t)
	w := httptest.NewRecorder()
	h.Advise(w, adviceReq(`{}`, clientID, secret))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestTransactionTypeStorageMem(t *testing.T) {
	s := NewMemStorage()
	now := time.Now().UTC()
	tt := TransactionType{TenantID: "ten_a", Name: "pay", ACR: "urn:xauth:protect:high:strict", CreatedAt: now}
	if err := s.CreateTransactionType(tt); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateTransactionType(tt); err != ErrConflict {
		t.Fatalf("dup: want ErrConflict, got %v", err)
	}
	_ = s.CreateTransactionType(TransactionType{TenantID: "ten_a", Name: "login", ACR: "urn:xauth:protect:high:protected", CreatedAt: now})
	_ = s.CreateTransactionType(TransactionType{TenantID: "ten_b", Name: "other", ACR: "urn:xauth:protect:ultra:strict", CreatedAt: now})

	list, _ := s.ListTransactionTypes("ten_a")
	if len(list) != 2 || list[0].Name != "login" || list[1].Name != "pay" { // name-ordered, tenant-scoped
		t.Fatalf("list ten_a: %+v", list)
	}
	if got, err := s.GetTransactionType("ten_a", "pay"); err != nil || got.ACR != tt.ACR {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := s.GetTransactionType("ten_a", "missing"); err != ErrNotFound {
		t.Errorf("missing: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteTransactionType("ten_a", "pay"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteTransactionType("ten_a", "pay"); err != ErrNotFound {
		t.Errorf("delete missing: want ErrNotFound, got %v", err)
	}
}
