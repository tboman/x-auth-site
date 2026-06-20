package internal

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// stubMDLVerifier returns a canned proof (or error) so the owner-console flow can
// be tested without a live id-service.
type stubMDLVerifier struct {
	proof MDLProof
	err   error
}

func (s stubMDLVerifier) Verify(_ context.Context, _, _ string) (MDLProof, error) {
	return s.proof, s.err
}

func newMDLRouter(t *testing.T, v MDLProofVerifier) (http.Handler, Storage) {
	t.Helper()
	store := NewMemStorage()
	r := Router(Deps{
		Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: &mockAuthenticator{}, Issuer: "http://test.local", Signer: testSigner,
		MDLVerifier: v,
	})
	return r, store
}

// The owner records a verified mDL: the trust anchor from the proof becomes a
// verified mdl identity anchor, shown on the Users tab.
func TestOwnerRecordMDL(t *testing.T) {
	r, store := newMDLRouter(t, stubMDLVerifier{proof: MDLProof{
		TrustAnchor: "CN=US-CA DMV IACA Root", IssuerCN: "CA DMV DS", VrfID: "vrf_1", IssuerTrusted: false,
	}})
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	oc := &http.Cookie{Name: ownerSessionCookie, Value: sessionCookie(w, ownerSessionCookie)}

	// A user in the workspace.
	mustUser(t, store, "usr_m", "ten_acme", "member@acme.test", time.Now().UTC())

	rw := postForm(t, r, "/admin/owner/identities/mdl",
		url.Values{"user_id": {"usr_m"}, "proof_token": {"any.jwt.token"}}, oc)
	if rw.Code != http.StatusFound {
		t.Fatalf("record mDL: want 302, got %d (%s)", rw.Code, rw.Body.String())
	}
	anchors, _ := store.ListIdentityAnchors("ten_acme")
	var got *IdentityAnchor
	for i := range anchors {
		if anchors[i].Type == AnchorMDL {
			got = &anchors[i]
		}
	}
	if got == nil || got.UserID != "usr_m" || got.Value != "CN=US-CA DMV IACA Root" || got.VerifiedAt == nil {
		t.Fatalf("mDL anchor wrong: %+v", got)
	}

	// The Users tab shows it in the mDL column.
	req := httptest.NewRequest(http.MethodGet, "/admin?tab=users", nil)
	req.AddCookie(oc)
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, req)
	if b := dw.Body.String(); !strings.Contains(b, ">mDL<") || !strings.Contains(b, "US-CA DMV IACA Root") {
		t.Fatalf("Users tab should show the mDL column + anchor:\n%s", b)
	}
}

// An invalid/foreign proof token is rejected; no anchor is written.
func TestOwnerRecordMDLRejectsBadProof(t *testing.T) {
	r, store := newMDLRouter(t, stubMDLVerifier{err: ErrMDLProofInvalid})
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	oc := &http.Cookie{Name: ownerSessionCookie, Value: sessionCookie(w, ownerSessionCookie)}
	mustUser(t, store, "usr_m", "ten_acme", "member@acme.test", time.Now().UTC())

	rw := postForm(t, r, "/admin/owner/identities/mdl",
		url.Values{"user_id": {"usr_m"}, "proof_token": {"bad"}}, oc)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("bad proof: want 400, got %d", rw.Code)
	}
	if anchors, _ := store.ListIdentityAnchors("ten_acme"); len(anchors) != 0 {
		t.Fatalf("no anchor should be written on a bad proof, got %d", len(anchors))
	}
}

// With no verifier configured (ID_ISSUER unset), recording reports not-implemented.
func TestOwnerRecordMDLNotConfigured(t *testing.T) {
	r, store := newMDLRouter(t, nil)
	w := driveSignup(t, r, store, "owner@acme.test", "Acme", "")
	oc := &http.Cookie{Name: ownerSessionCookie, Value: sessionCookie(w, ownerSessionCookie)}
	mustUser(t, store, "usr_m", "ten_acme", "member@acme.test", time.Now().UTC())
	rw := postForm(t, r, "/admin/owner/identities/mdl",
		url.Values{"user_id": {"usr_m"}, "proof_token": {"x"}}, oc)
	if rw.Code != http.StatusNotImplemented {
		t.Fatalf("no verifier: want 501, got %d", rw.Code)
	}
}

// The HTTP verifier binds a proof to its audience and acr: a token for another
// tenant, or one lacking the mDL acr, is rejected.
func TestHTTPMDLProofVerifierBindings(t *testing.T) {
	signer := testSigner
	jwks, err := json.Marshal(signer.JWKS())
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(jwks)
	}))
	defer srv.Close()
	v := NewHTTPMDLProofVerifier("http://id.test", srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mint := func(aud, acr string) string {
		tok, _ := signer.Sign(jwtx.Claims{
			Iss: "http://id.test", Aud: aud, ACR: acr, AMR: []string{"mdl"},
			Iat: time.Now().UTC().Unix(), Exp: time.Now().UTC().Add(5 * time.Minute).Unix(), JTI: "prf_x",
		}, map[string]any{"trust_anchor": "Root X", "issuer_cn": "DS", "vrf_id": "v1", "issuer_trusted": false})
		return tok
	}

	if p, err := v.Verify(context.Background(), mint("ten_acme", mdlProofACR), "ten_acme"); err != nil || p.TrustAnchor != "Root X" {
		t.Fatalf("valid proof should pass: %+v err=%v", p, err)
	}
	if _, err := v.Verify(context.Background(), mint("ten_other", mdlProofACR), "ten_acme"); err == nil {
		t.Fatal("audience mismatch should fail")
	}
	if _, err := v.Verify(context.Background(), mint("ten_acme", "urn:other"), "ten_acme"); err == nil {
		t.Fatal("non-mDL acr should fail")
	}
}
