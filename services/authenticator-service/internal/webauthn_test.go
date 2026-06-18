package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/xentranet/x-auth/pkg/webauthnx"
)

func testWA(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthnx.New(webauthnx.Config{RPID: "localhost", RPOrigins: []string{"http://localhost"}}, nil)
	if err != nil {
		t.Fatalf("webauthnx.New: %v", err)
	}
	return wa
}

// credentialToMetadata → JSON round-trip (as PG would) → credentialFromMetadata
// preserves every field, with the sign count surviving the float64 coercion.
func TestCredentialMetadataRoundTrip(t *testing.T) {
	cred := &webauthn.Credential{
		ID:              []byte{1, 2, 3, 4},
		PublicKey:       []byte{9, 8, 7},
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{"internal", "hybrid"},
		Flags:           webauthn.CredentialFlags{BackupEligible: true, BackupState: false},
		Authenticator:   webauthn.Authenticator{AAGUID: []byte{5, 6}, SignCount: 42, Attachment: "platform"},
	}
	m := credentialToMetadata(cred)

	raw, err := json.Marshal(m) // numbers become float64 on the way back, like a JSONB read
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(raw, &m2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := credentialFromMetadata(m2)
	if err != nil {
		t.Fatalf("fromMetadata: %v", err)
	}
	if !bytes.Equal(got.ID, cred.ID) || !bytes.Equal(got.PublicKey, cred.PublicKey) {
		t.Fatalf("id/public_key not preserved: %+v", got)
	}
	if got.Authenticator.SignCount != 42 {
		t.Fatalf("sign_count = %d, want 42", got.Authenticator.SignCount)
	}
	if !bytes.Equal(got.Authenticator.AAGUID, cred.Authenticator.AAGUID) {
		t.Fatalf("aaguid not preserved")
	}
	if len(got.Transport) != 2 || got.Transport[0] != "internal" {
		t.Fatalf("transports = %v", got.Transport)
	}
	if !got.Flags.BackupEligible || got.Flags.BackupState {
		t.Fatalf("flags = %+v", got.Flags)
	}
}

// With no enrolled passkey the assertion adapter signals errNoCredential so the
// caller can run registration first.
func TestWebAuthnDispatchNoCredential(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	a := &webauthnAdapter{log: log, store: store, wa: testWA(t)}

	_, err := a.Dispatch(context.Background(), Challenge{TenantID: "t", UserID: "u", Method: MethodFIDO2})
	if !errors.Is(err, errNoCredential) {
		t.Fatalf("want errNoCredential, got %v", err)
	}
}

func TestAmrFor(t *testing.T) {
	if got := amrFor(true); len(got) != 2 || got[0] != "user" || got[1] != "pin" {
		t.Fatalf("UV amr = %v, want [user pin]", got)
	}
	if got := amrFor(false); len(got) != 2 || got[0] != "user" || got[1] != "swk" {
		t.Fatalf("no-UV amr = %v, want [user swk]", got)
	}
}

// fido2 can't be enrolled by posting raw metadata — it must go through the
// registration ceremony.
func TestEnrollRejectsFIDO2(t *testing.T) {
	srv, _, _ := newTestServer(t)
	resp := do(t, srv, http.MethodPost, "/v1/authenticators", EnrollRequest{
		UserID: "u1", Method: MethodFIDO2, Metadata: map[string]any{"credential_id": "forged"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll fido2: want 400, got %d", resp.StatusCode)
	}
	var body errorBody
	decode(t, resp, &body)
	if body.Error != "use_registration_ceremony" {
		t.Fatalf("error = %q, want use_registration_ceremony", body.Error)
	}
}

// The WebAuthn ceremony columns (options_json / session_data) round-trip on the
// in-memory store; non-WebAuthn challenges leave them empty.
func TestChallengeWebAuthnFieldsRoundTripMem(t *testing.T) {
	clock := &testClock{t: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)}
	store := NewStore(clock.now)
	c := Challenge{
		ID: "ch_w", TenantID: "t", UserID: "u", Method: MethodFIDO2, Status: ChallengeStatusPending,
		CreatedAt: clock.now(), ExpiresAt: clock.now().Add(time.Minute),
		OptionsJSON: `{"publicKey":{"challenge":"abc"}}`, SessionData: []byte("session-bytes"),
	}
	if err := store.PutChallenge(c); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.GetChallenge("t", "ch_w")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.OptionsJSON != c.OptionsJSON {
		t.Fatalf("options_json = %q", got.OptionsJSON)
	}
	if string(got.SessionData) != "session-bytes" {
		t.Fatalf("session_data = %q", got.SessionData)
	}
}
