package internal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubIDClient returns canned verification responses.
type stubIDClient struct {
	createID, createURL string
	createErr           error
	getStatus, getProof string
	getErr              error
}

func (s stubIDClient) Create(_ context.Context, _, _ string, _ []string, _ string) (string, string, error) {
	return s.createID, s.createURL, s.createErr
}
func (s stubIDClient) Get(_ context.Context, _, _ string) (string, string, error) {
	return s.getStatus, s.getProof, s.getErr
}

func newEnrollRouter(t *testing.T, id IDVerificationClient, v MDLProofVerifier) (http.Handler, Storage) {
	t.Helper()
	store := NewMemStorage()
	r := Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		MDLVerifier: v, IDClient: id,
	})
	return r, store
}

// seedEnrollSession creates a user + enrollment session and returns the cookie.
func seedEnrollSession(t *testing.T, store Storage, tenantID, userID, email string) *http.Cookie {
	t.Helper()
	now := time.Now().UTC()
	mustUser(t, store, userID, tenantID, email, now)
	sess := Session{ID: "ses_enr", TenantID: tenantID, UserID: userID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	if _, err := store.CreateSession(sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return &http.Cookie{Name: enrollSessionCookie, Value: tenantID + "|" + sess.ID}
}

func TestEnrollMDLStartRejectsUnknownClient(t *testing.T) {
	r, _ := newEnrollRouter(t, stubIDClient{}, stubMDLVerifier{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/mdl?client_id=nope", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown client: want 400, got %d", w.Code)
	}
}

func TestEnrollMDLPageRendersBothPaths(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{createID: "vrf_1", createURL: "https://id.x-auth.com/v/tok"},
		stubMDLVerifier{})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/page", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("page: want 200, got %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"On this device", "https://id.x-auth.com/v/tok", "data:image/png;base64,", "/enroll/mdl/status"} {
		if !strings.Contains(b, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// The verification id is parked in a browser-bound cookie for polling.
	if !strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), " "), enrollVrfCookie) {
		t.Error("page should set the vrf cookie")
	}
}

func TestEnrollMDLStatusPending(t *testing.T) {
	r, store := newEnrollRouter(t, stubIDClient{getStatus: "pending"}, stubMDLVerifier{})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil)
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: enrollVrfCookie, Value: "vrf_1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"status":"pending"`) {
		t.Fatalf("want pending, got %s", w.Body.String())
	}
}

func TestEnrollMDLStatusVerifiedCreatesAnchor(t *testing.T) {
	r, store := newEnrollRouter(t,
		stubIDClient{getStatus: "verified", getProof: "proof.jwt"},
		stubMDLVerifier{proof: MDLProof{TrustAnchor: "CN=NY DMV IACA"}})
	cookie := seedEnrollSession(t, store, "ten_acme", "usr_e", "e@acme.test")
	req := httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil)
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: enrollVrfCookie, Value: "vrf_1"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `"status":"done"`) || !strings.Contains(w.Body.String(), "NY DMV IACA") {
		t.Fatalf("want done + anchor, got %s", w.Body.String())
	}
	anchors, _ := store.ListIdentityAnchors("ten_acme")
	var got *IdentityAnchor
	for i := range anchors {
		if anchors[i].Type == AnchorMDL {
			got = &anchors[i]
		}
	}
	if got == nil || got.UserID != "usr_e" || got.Value != "CN=NY DMV IACA" || got.VerifiedAt == nil {
		t.Fatalf("mdl anchor wrong: %+v", got)
	}
}

func TestEnrollMDLStatusNoSession(t *testing.T) {
	r, _ := newEnrollRouter(t, stubIDClient{}, stubMDLVerifier{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/enroll/mdl/status", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"status":"expired"`) {
		t.Fatalf("no session: want 401 expired, got %d %s", w.Code, w.Body.String())
	}
}
