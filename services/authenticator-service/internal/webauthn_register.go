package internal

// webauthn_register.go is the passkey REGISTRATION ceremony (enrolling a new
// credential). It can't reuse the generic challenge lifecycle because there's no
// pre-existing credential to challenge, so it has its own begin/finish endpoints
// with a short-TTL in-memory session store (single-replica caveat, like the
// authentication-service parked flows). Assertion (login) lives in webauthn.go.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

const webauthnRegTTL = 10 * time.Minute

// WebAuthnRegisterBeginRequest / Response and FinishRequest are the wire shapes
// for the two-step registration ceremony.
type WebAuthnRegisterBeginRequest struct {
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type WebAuthnRegisterBeginResponse struct {
	RegistrationID string          `json:"registration_id"`
	Options        json.RawMessage `json:"options"`
}

type WebAuthnRegisterFinishRequest struct {
	UserID         string          `json:"user_id"`
	RegistrationID string          `json:"registration_id"`
	Attestation    json.RawMessage `json:"attestation"`
}

type regSession struct {
	data        webauthn.SessionData
	tenantID    string
	userID      string
	name        string
	displayName string
	createdAt   time.Time
}

// WebAuthnHandlers serves the passkey registration ceremony.
type WebAuthnHandlers struct {
	log   *slog.Logger
	store Storage
	wa    *webauthn.WebAuthn

	mu       sync.Mutex
	sessions map[string]regSession
}

// NewWebAuthnHandlers constructs the registration handler bundle.
func NewWebAuthnHandlers(log *slog.Logger, store Storage, wa *webauthn.WebAuthn) *WebAuthnHandlers {
	return &WebAuthnHandlers{log: log, store: store, wa: wa, sessions: map[string]regSession{}}
}

func (h *WebAuthnHandlers) park(id string, s regSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := h.store.Now().Add(-webauthnRegTTL)
	for k, v := range h.sessions {
		if v.createdAt.Before(cutoff) {
			delete(h.sessions, k)
		}
	}
	h.sessions[id] = s
}

func (h *WebAuthnHandlers) take(id string) (regSession, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[id]
	if !ok {
		return regSession{}, false
	}
	delete(h.sessions, id) // single-use
	if h.store.Now().Sub(s.createdAt) > webauthnRegTTL {
		return regSession{}, false
	}
	return s, true
}

// RegisterBegin starts a registration: it returns the credential creation
// options and parks the ceremony session under a registration_id.
func (h *WebAuthnHandlers) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	var req WebAuthnRegisterBeginRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}

	user, err := loadWebAuthnUser(h.store, h.log, tenantID, req.UserID, req.Name, req.DisplayName)
	if err != nil {
		h.log.Error("webauthn_register_load_user_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load user")
		return
	}
	// Exclude already-registered credentials so the same authenticator isn't
	// enrolled twice.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.creds))
	for _, c := range user.creds {
		exclusions = append(exclusions, c.Descriptor())
	}

	creation, session, err := h.wa.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		h.log.Error("webauthn_begin_registration_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusBadGateway, "registration_failed", "could not begin registration")
		return
	}
	options, err := json.Marshal(creation)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not encode options")
		return
	}

	regID := "reg_" + uuid.NewString()
	h.park(regID, regSession{
		data: *session, tenantID: tenantID, userID: req.UserID,
		name: req.Name, displayName: req.DisplayName, createdAt: h.store.Now(),
	})
	h.log.Info("webauthn_registration_begun", "registration_id", regID, "user_id", req.UserID, "tenant_id", tenantID)
	httpx.WriteJSON(w, http.StatusOK, WebAuthnRegisterBeginResponse{RegistrationID: regID, Options: options})
}

// RegisterFinish validates the attestation against the parked session and, on
// success, persists a new active fido2 authenticator holding the credential.
func (h *WebAuthnHandlers) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	var req WebAuthnRegisterFinishRequest
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed json body")
		return
	}
	if req.UserID == "" || req.RegistrationID == "" || len(req.Attestation) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "user_id, registration_id and attestation are required")
		return
	}

	session, ok := h.take(req.RegistrationID)
	if !ok || session.tenantID != tenantID || session.userID != req.UserID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_registration", "unknown or expired registration session")
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Attestation))
	if err != nil {
		h.log.Info("webauthn_attestation_parse_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_attestation", "could not parse attestation")
		return
	}
	user, err := loadWebAuthnUser(h.store, h.log, tenantID, req.UserID, session.name, session.displayName)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not load user")
		return
	}
	cred, err := h.wa.CreateCredential(user, session.data, parsed)
	if err != nil {
		h.log.Info("webauthn_attestation_rejected", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_attestation", "attestation verification failed")
		return
	}

	now := h.store.Now()
	authr := Authenticator{
		ID:        "authr_" + uuid.NewString(),
		TenantID:  tenantID,
		UserID:    req.UserID,
		Method:    MethodFIDO2,
		Metadata:  credentialToMetadata(cred),
		Status:    AuthenticatorStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.PutAuthenticator(authr); err != nil {
		h.log.Error("webauthn_authenticator_put_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not store credential")
		return
	}
	h.log.Info("webauthn_registered", "authenticator_id", authr.ID, "user_id", req.UserID, "tenant_id", tenantID)
	httpx.WriteJSON(w, http.StatusCreated, authr)
}
