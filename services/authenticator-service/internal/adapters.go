package internal

import (
	"context"
	"errors"
	"log/slog"
)

// Adapter is the per-method vendor boundary. Phase 1 has five pure-Go stubs;
// phase 2 swaps them for SDK-backed implementations (Yubico / webauthn-go,
// pquerna/otp, Twilio, APNs/FCM, SendGrid). The interface stays frozen.
type Adapter interface {
	// Dispatch kicks off the authentication ceremony. For WebAuthn this is
	// producing the challenge bytes; for TOTP it is a no-op prompt; for push/
	// sms/magic_link it is the outbound send. Returns the user-visible prompt
	// text to surface on the client.
	Dispatch(ctx context.Context, chal Challenge) (prompt string, err error)

	// Verify checks the response submitted by the client. The `response` map
	// is method-specific — see each stub below for the accepted shape.
	Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error)
}

// Registry indexes adapters by method name. One per process.
type Registry struct {
	log      *slog.Logger
	adapters map[string]Adapter
}

// NewRegistry wires the phase-1 stubs into a Registry. Every adapter is
// constructed with the same logger so dispatch/verify traces appear on a
// single stream.
func NewRegistry(log *slog.Logger) *Registry {
	return &Registry{
		log: log,
		adapters: map[string]Adapter{
			MethodFIDO2:     &webauthnAdapter{log: log},
			MethodTOTP:      &totpAdapter{log: log},
			MethodPush:      &pushAdapter{log: log},
			MethodSMS:       &smsAdapter{log: log},
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

// -----------------------------------------------------------------------------
// webauthn / FIDO2
// -----------------------------------------------------------------------------

type webauthnAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — back this with github.com/go-webauthn/webauthn
// or a Yubico/DUO SDK; generate a real challenge, persist rp_id & allowed creds,
// and verify assertion signature against the stored public key.
func (a *webauthnAdapter) Dispatch(ctx context.Context, chal Challenge) (string, error) {
	a.log.Info("adapter_dispatch", "method", MethodFIDO2, "challenge_id", chal.ID)
	return "WebAuthn ceremony initiated (stub)", nil
}

// TODO(phase-2): real vendor adapter — verify clientDataJSON / authenticatorData
// bindings and signature over the challenge bytes.
func (a *webauthnAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error) {
	a.log.Info("adapter_verify", "method", MethodFIDO2, "challenge_id", chal.ID)
	sig, _ := getString(response, "signature")
	return sig == "stub_valid_signature", nil
}

// -----------------------------------------------------------------------------
// TOTP
// -----------------------------------------------------------------------------

type totpAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — back this with github.com/pquerna/otp,
// derive the 30s window from the enrollment's shared secret in metadata.
func (a *totpAdapter) Dispatch(ctx context.Context, chal Challenge) (string, error) {
	a.log.Info("adapter_dispatch", "method", MethodTOTP, "challenge_id", chal.ID)
	return "Enter 6-digit code from your authenticator app", nil
}

// TODO(phase-2): real vendor adapter — totp.Validate against stored secret +/- 1 window.
func (a *totpAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error) {
	a.log.Info("adapter_verify", "method", MethodTOTP, "challenge_id", chal.ID)
	code, _ := getString(response, "code")
	return code == "000000", nil
}

// -----------------------------------------------------------------------------
// Push
// -----------------------------------------------------------------------------

type pushAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — integrate APNs / FCM (or Duo Push) using
// the device token stored on the authenticator metadata.
func (a *pushAdapter) Dispatch(ctx context.Context, chal Challenge) (string, error) {
	a.log.Info("adapter_dispatch", "method", MethodPush, "challenge_id", chal.ID)
	return "Push notification sent (stub)", nil
}

// TODO(phase-2): real vendor adapter — poll/subscribe to the push vendor's
// approval webhook instead of accepting a client-asserted boolean.
func (a *pushAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error) {
	a.log.Info("adapter_verify", "method", MethodPush, "challenge_id", chal.ID)
	approved, _ := getBool(response, "approved")
	return approved, nil
}

// -----------------------------------------------------------------------------
// SMS
// -----------------------------------------------------------------------------

type smsAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — call Twilio Verify or MessageBird to send
// an OTP to the phone number on the authenticator metadata.
func (a *smsAdapter) Dispatch(ctx context.Context, chal Challenge) (string, error) {
	a.log.Info("adapter_dispatch", "method", MethodSMS, "challenge_id", chal.ID)
	return "SMS OTP sent to +15551234 (stub)", nil
}

// TODO(phase-2): real vendor adapter — verify against the code the vendor
// generated, not a hard-coded literal.
func (a *smsAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error) {
	a.log.Info("adapter_verify", "method", MethodSMS, "challenge_id", chal.ID)
	code, _ := getString(response, "code")
	return code == "123456", nil
}

// -----------------------------------------------------------------------------
// Magic link (email)
// -----------------------------------------------------------------------------

type magicLinkAdapter struct{ log *slog.Logger }

// TODO(phase-2): real vendor adapter — SendGrid / SES; mint a short-lived
// signed token, embed in a URL, persist the token hash.
func (a *magicLinkAdapter) Dispatch(ctx context.Context, chal Challenge) (string, error) {
	a.log.Info("adapter_dispatch", "method", MethodMagicLink, "challenge_id", chal.ID)
	return "Magic link sent to user@example.com (stub)", nil
}

// TODO(phase-2): real vendor adapter — constant-time compare against the
// persisted token hash, check expiry.
func (a *magicLinkAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (bool, error) {
	a.log.Info("adapter_verify", "method", MethodMagicLink, "challenge_id", chal.ID)
	tok, _ := getString(response, "token")
	return tok == "stub_magic_token", nil
}
