package internal

// webauthn.go is the real FIDO2/passkey adapter, backed by
// github.com/go-webauthn/webauthn. Assertion (step-up login) runs through the
// generic challenge lifecycle: Dispatch produces the request options + the
// server-only SessionData (persisted on the challenge), and Verify validates the
// assertion against the user's stored credentials and writes back the sign
// counter. Registration (enrolling a passkey) is in webauthn_register.go.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type webauthnAdapter struct {
	log   *slog.Logger
	store Storage
	wa    *webauthn.WebAuthn
}

// errNoCredential signals that the user has no enrolled passkey, so the caller
// must run registration first.
var errNoCredential = errors.New("user has no fido2 credential")

// Dispatch begins an assertion: it builds the request options for the user's
// registered passkeys and returns the options (for the browser) + the SessionData
// (persisted on the challenge for Verify).
func (a *webauthnAdapter) Dispatch(ctx context.Context, chal Challenge) (DispatchResult, error) {
	a.log.Info("adapter_dispatch", "method", MethodFIDO2, "challenge_id", chal.ID)
	user, err := a.loadUser(chal.TenantID, chal.UserID, "", "")
	if err != nil {
		return DispatchResult{}, err
	}
	if len(user.creds) == 0 {
		return DispatchResult{}, errNoCredential
	}
	assertion, session, err := a.wa.BeginLogin(user)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("begin login: %w", err)
	}
	options, err := json.Marshal(assertion)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("marshal options: %w", err)
	}
	sd, err := json.Marshal(session)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("marshal session: %w", err)
	}
	return DispatchResult{Prompt: "Use your passkey to continue", Options: string(options), SessionData: sd}, nil
}

// Verify validates the submitted assertion (response["assertion"]) against the
// challenge's SessionData, writes the new sign counter back to the matching
// authenticator, and reports the achieved AMR. A validation failure (bad/forged
// assertion, counter regression) is OK:false with a nil error so it counts as a
// failed attempt; only storage/internal faults return an error.
func (a *webauthnAdapter) Verify(ctx context.Context, chal Challenge, response map[string]any) (VerifyResult, error) {
	a.log.Info("adapter_verify", "method", MethodFIDO2, "challenge_id", chal.ID)
	if len(chal.SessionData) == 0 {
		return VerifyResult{}, errors.New("challenge missing webauthn session data")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(chal.SessionData, &session); err != nil {
		return VerifyResult{}, fmt.Errorf("decode session: %w", err)
	}

	raw, ok := response["assertion"]
	if !ok {
		return VerifyResult{OK: false}, nil
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return VerifyResult{OK: false}, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		a.log.Info("webauthn_assertion_parse_failed", "challenge_id", chal.ID, "err", err)
		return VerifyResult{OK: false}, nil
	}

	user, err := a.loadUser(chal.TenantID, chal.UserID, "", "")
	if err != nil {
		return VerifyResult{}, err
	}
	cred, err := a.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		a.log.Info("webauthn_assertion_rejected", "challenge_id", chal.ID, "err", err)
		return VerifyResult{OK: false}, nil
	}
	if cred.Authenticator.CloneWarning {
		// Sign-counter regression: a cloned authenticator may exist. Reject.
		a.log.Warn("webauthn_counter_regression", "challenge_id", chal.ID, "user_id", chal.UserID)
		return VerifyResult{OK: false}, nil
	}

	// Persist the incremented sign counter on the matching authenticator.
	if err := a.updateCounter(chal.TenantID, chal.UserID, cred); err != nil {
		a.log.Error("webauthn_counter_persist_failed", "err", err, "challenge_id", chal.ID)
		// The assertion was valid; don't fail the user over a counter write.
	}

	return VerifyResult{OK: true, AMR: amrFor(cred.Flags.UserVerified)}, nil
}

// amrFor maps the verified user-verification flag to RFC 8176 AMR values.
func amrFor(userVerified bool) []string {
	if userVerified {
		return []string{"user", "pin"} // user verification (biometric/PIN) performed
	}
	return []string{"user", "swk"} // user presence only, software key
}

// updateCounter writes cred's new sign count back to the authenticator whose
// stored credential_id matches.
func (a *webauthnAdapter) updateCounter(tenantID, userID string, cred *webauthn.Credential) error {
	auths, err := a.store.ListActiveAuthenticators(tenantID, userID)
	if err != nil {
		return err
	}
	want := base64.RawURLEncoding.EncodeToString(cred.ID)
	for _, authr := range auths {
		if authr.Method != MethodFIDO2 {
			continue
		}
		if id, _ := authr.Metadata["credential_id"].(string); id != want {
			continue
		}
		authr.Metadata["sign_count"] = float64(cred.Authenticator.SignCount)
		authr.UpdatedAt = a.store.Now()
		return a.store.PutAuthenticator(authr)
	}
	return nil // credential not found among active rows — nothing to update
}

func (a *webauthnAdapter) loadUser(tenantID, userID, name, displayName string) (*webauthnUser, error) {
	return loadWebAuthnUser(a.store, a.log, tenantID, userID, name, displayName)
}

// loadWebAuthnUser builds a webauthn.User for (tenant, user) from their active
// fido2 authenticators. name/displayName are used at registration only;
// assertion passes "" and falls back to the user id.
func loadWebAuthnUser(store Storage, log *slog.Logger, tenantID, userID, name, displayName string) (*webauthnUser, error) {
	auths, err := store.ListActiveAuthenticators(tenantID, userID)
	if err != nil {
		return nil, err
	}
	var creds []webauthn.Credential
	for _, authr := range auths {
		if authr.Method != MethodFIDO2 {
			continue
		}
		c, err := credentialFromMetadata(authr.Metadata)
		if err != nil {
			log.Error("webauthn_decode_credential_failed", "err", err, "authenticator_id", authr.ID)
			continue
		}
		creds = append(creds, c)
	}
	if name == "" {
		name = userID
	}
	if displayName == "" {
		displayName = name
	}
	return &webauthnUser{id: []byte(userID), name: name, displayName: displayName, creds: creds}, nil
}

// webauthnUser adapts an X-Auth user to the go-webauthn User interface. The
// handle is the opaque usr_<uuid> id (never email — it's stored on-device).
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnIcon() string                       { return "" }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// credentialToMetadata serializes a webauthn.Credential into the JSONB-friendly
// metadata map stored on a fido2 authenticator (base64url for binary fields).
func credentialToMetadata(c *webauthn.Credential) map[string]any {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return map[string]any{
		"credential_id":    base64.RawURLEncoding.EncodeToString(c.ID),
		"public_key":       base64.RawURLEncoding.EncodeToString(c.PublicKey),
		"attestation_type": c.AttestationType,
		"transports":       transports,
		"aaguid":           base64.RawURLEncoding.EncodeToString(c.Authenticator.AAGUID),
		"sign_count":       float64(c.Authenticator.SignCount),
		"backup_eligible":  c.Flags.BackupEligible,
		"backup_state":     c.Flags.BackupState,
		"attachment":       string(c.Authenticator.Attachment),
		"enrolled_by":      "authorize-fido2-register",
	}
}

// credentialFromMetadata reverses credentialToMetadata. Numbers may arrive as
// float64 (JSON round-trip) or int (in-memory store).
func credentialFromMetadata(m map[string]any) (webauthn.Credential, error) {
	id, err := decodeB64(m, "credential_id")
	if err != nil {
		return webauthn.Credential{}, err
	}
	pub, err := decodeB64(m, "public_key")
	if err != nil {
		return webauthn.Credential{}, err
	}
	aaguid, _ := decodeB64(m, "aaguid")
	var transports []protocol.AuthenticatorTransport
	if ts, ok := m["transports"].([]any); ok {
		for _, t := range ts {
			if s, ok := t.(string); ok {
				transports = append(transports, protocol.AuthenticatorTransport(s))
			}
		}
	}
	attType, _ := m["attestation_type"].(string)
	att, _ := m["attachment"].(string)
	be, _ := m["backup_eligible"].(bool)
	bs, _ := m["backup_state"].(bool)
	return webauthn.Credential{
		ID:              id,
		PublicKey:       pub,
		AttestationType: attType,
		Transport:       transports,
		Flags:           webauthn.CredentialFlags{BackupEligible: be, BackupState: bs},
		Authenticator: webauthn.Authenticator{
			AAGUID:     aaguid,
			SignCount:  asUint32(m["sign_count"]),
			Attachment: protocol.AuthenticatorAttachment(att),
		},
	}, nil
}

func decodeB64(m map[string]any, key string) ([]byte, error) {
	s, _ := m[key].(string)
	if s == "" {
		return nil, fmt.Errorf("webauthn metadata missing %q", key)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("webauthn metadata %q: %w", key, err)
	}
	return b, nil
}

func asUint32(v any) uint32 {
	switch n := v.(type) {
	case float64:
		return uint32(n)
	case int:
		return uint32(n)
	case int64:
		return uint32(n)
	case json.Number:
		i, _ := n.Int64()
		return uint32(i)
	default:
		return 0
	}
}
