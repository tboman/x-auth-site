package internal

import (
	"context"
	"errors"
	"log/slog"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/xentranet/x-auth/pkg/smsx"
)

// DispatchResult is what Dispatch hands back. Prompt is the user-visible text;
// for WebAuthn, Options is the PublicKeyCredentialRequestOptions surfaced to the
// browser and SessionData is the server-only ceremony state persisted on the
// challenge. Non-WebAuthn methods set only Prompt.
type DispatchResult struct {
	Prompt      string
	Options     string // PublicKeyCredentialRequestOptions JSON (fido2 only)
	SessionData []byte // serialized go-webauthn SessionData (fido2 only)
}

// VerifyResult is what Verify hands back. OK is whether the response validated;
// AMR is the method-derived authentication-method references actually achieved
// (e.g. WebAuthn with user verification → ["user","pin"]). AMR is nil when the
// method has no dynamic AMR and the caller uses its configured default.
type VerifyResult struct {
	OK  bool
	AMR []string
}

// Adapter is the per-method vendor boundary. SMS (Twilio) and FIDO2 (WebAuthn)
// are real; TOTP/push/magic_link are still phase-1 stubs.
type Adapter interface {
	// Dispatch kicks off the authentication ceremony — producing the WebAuthn
	// request options, a TOTP no-op prompt, or the SMS/push/email outbound send.
	Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error)

	// Verify checks the response submitted by the client. The `response` map is
	// method-specific — see each adapter below for the accepted shape.
	Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error)
}

// Registry indexes adapters by method name. One per process.
type Registry struct {
	log      *slog.Logger
	adapters map[string]Adapter
}

// NewRegistry wires the adapters into a Registry. Every adapter shares the
// logger. SMS gets the store + an smsx.Verifier; FIDO2 gets the store + the
// configured *webauthn.WebAuthn relying party; TOTP/push/magic_link are stubs.
func NewRegistry(log *slog.Logger, store Storage, verifier smsx.Verifier, wa *webauthn.WebAuthn) *Registry {
	return &Registry{
		log: log,
		adapters: map[string]Adapter{
			MethodFIDO2:     &webauthnAdapter{log: log, store: store, wa: wa},
			MethodTOTP:      &totpAdapter{log: log},
			MethodPush:      &pushAdapter{log: log},
			MethodSMS:       &smsAdapter{log: log, store: store, verifier: verifier},
			MethodMagicLink: &magicLinkAdapter{log: log},
		},
	}
}

// Lookup returns the adapter for method, or (nil, false) if not registered.
func (r *Registry) Lookup(method string) (Adapter, bool) {
	a, ok := r.adapters[method]
	return a, ok
}

// ErrUnsupportedMethod is returned if a dispatch/verify is attempted against
// a method with no registered adapter. Should only happen on a programmer
// error because IsValidMethod is the first gate on every handler.
var ErrUnsupportedMethod = errors.New("unsupported method")

// -----------------------------------------------------------------------------
// stub helpers
// -----------------------------------------------------------------------------

// getString pulls a string field out of a response map, tolerating missing
// keys. Returns ("", false) for wrong-type values so adapters never panic on
// garbage input.
func getString(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// getBool pulls a bool field out of a response map. Same leniency as getString.
func getBool(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// webauthnAdapter (FIDO2/passkeys) lives in webauthn.go — it's backed by
// github.com/go-webauthn/webauthn and needs the store + relying party.

// -----------------------------------------------------------------------------
// TOTP
// -----------------------------------------------------------------------------

type totpAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — back this with github.com/pquerna/otp,
// derive the 30s window from the enrollment's shared secret in metadata.
func (a *totpAdapter) Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error) {
	a.log.Info("adapter_dispatch", "method", MethodTOTP, "challenge_id", chal.ID)
	return DispatchResult{Prompt: "Enter 6-digit code from your authenticator app"}, nil
}

// TODO(phase-2): real vendor adapter — totp.Validate against stored secret +/- 1 window.
func (a *totpAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error) {
	a.log.Info("adapter_verify", "method", MethodTOTP, "challenge_id", chal.ID)
	code, _ := getString(response, "code")
	return VerifyResult{OK: code == "000000"}, nil
}

// -----------------------------------------------------------------------------
// Push
// -----------------------------------------------------------------------------

type pushAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — integrate APNs / FCM (or Duo Push) using
// the device token stored on the authenticator metadata.
func (a *pushAdapter) Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error) {
	a.log.Info("adapter_dispatch", "method", MethodPush, "challenge_id", chal.ID)
	return DispatchResult{Prompt: "Push notification sent (stub)"}, nil
}

// TODO(phase-2): real vendor adapter — poll/subscribe to the push vendor's
// approval webhook instead of accepting a client-asserted boolean.
func (a *pushAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error) {
	a.log.Info("adapter_verify", "method", MethodPush, "challenge_id", chal.ID)
	approved, _ := getBool(response, "approved")
	return VerifyResult{OK: approved}, nil
}

// -----------------------------------------------------------------------------
// SMS
// -----------------------------------------------------------------------------

type smsAdapter struct {
	log      *slog.Logger
	store    Storage
	verifier smsx.Verifier
}

// phone reads the enrollment's verified number off the authenticator referenced
// by the challenge (set when the step-up enrolled the SMS authenticator).
func (a *smsAdapter) phone(chal Challenge) (string, error) {
	authr, err := a.store.GetAuthenticator(chal.TenantID, chal.AuthenticatorID)
	if err != nil {
		return "", err
	}
	p, _ := authr.Metadata["phone_number"].(string)
	if p == "" {
		return "", errors.New("authenticator has no phone_number")
	}
	return p, nil
}

// Dispatch texts a fresh code to the enrolled number via the verifier.
func (a *smsAdapter) Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error) {
	a.log.Info("adapter_dispatch", "method", MethodSMS, "challenge_id", chal.ID)
	phone, err := a.phone(chal)
	if err != nil {
		return DispatchResult{}, err
	}
	if err := a.verifier.Start(ctx, phone); err != nil {
		return DispatchResult{}, err
	}
	return DispatchResult{Prompt: "We texted a verification code to your phone"}, nil
}

// Verify checks the submitted code against the verifier (Twilio Verify validates
// it; the stub accepts smsx.StubCode).
func (a *smsAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error) {
	a.log.Info("adapter_verify", "method", MethodSMS, "challenge_id", chal.ID)
	phone, err := a.phone(chal)
	if err != nil {
		return VerifyResult{}, err
	}
	code, _ := getString(response, "code")
	ok, err := a.verifier.Check(ctx, phone, code)
	return VerifyResult{OK: ok}, err
}

// -----------------------------------------------------------------------------
// Magic link (email)
// -----------------------------------------------------------------------------

type magicLinkAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — SendGrid / SES; mint a short-lived
// signed token, embed in a URL, persist the token hash.
func (a *magicLinkAdapter) Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error) {
	a.log.Info("adapter_dispatch", "method", MethodMagicLink, "challenge_id", chal.ID)
	return DispatchResult{Prompt: "Magic link sent to user@example.com (stub)"}, nil
}

// TODO(phase-2): real vendor adapter — constant-time compare against the
// persisted token hash, check expiry.
func (a *magicLinkAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error) {
	a.log.Info("adapter_verify", "method", MethodMagicLink, "challenge_id", chal.ID)
	tok, _ := getString(response, "token")
	return VerifyResult{OK: tok == "stub_magic_token"}, nil
}
