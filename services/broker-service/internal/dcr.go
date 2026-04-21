package internal

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// DCRHandlers implements RFC 7591 Dynamic Client Registration.
// The broker accepts a free-form client_metadata JSON object, assigns a client_id
// and client_secret (both random UUIDs in phase 1), stores the record in memory,
// and returns the registered client per RFC 7591 §3.2.1.
//
// Phase 1 skips:
//   - initial access tokens (anyone can register)
//   - software statements (not validated)
//   - client authentication on registration (accepted anonymously)
//
// TODO(phase-2): validate redirect_uris, enforce tenant-scoped registration,
// issue signed client_secret tokens, publish registration_access_token + registration_client_uri.
type DCRHandlers struct {
	Store  Storage
	Logger *slog.Logger
}

// Register handles POST /register per RFC 7591. The entire request body is
// treated as opaque client metadata — any known fields (redirect_uris, grant_types,
// etc.) are echoed back to the caller in the response, plus the assigned ids.
func (h *DCRHandlers) Register(w http.ResponseWriter, r *http.Request) {
	var metadata map[string]any
	if err := httpx.ReadJSON(r, &metadata); err != nil {
		if errors.Is(err, io.EOF) {
			// RFC 7591 allows empty registrations, but requires at least an empty object.
			metadata = map[string]any{}
		} else {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
	}

	client := DCRClient{
		ClientID:       uuid.NewString(),
		ClientSecret:   uuid.NewString(),
		ClientMetadata: metadata,
		CreatedAt:      time.Now().UTC(),
	}
	if err := h.Store.PutClient(client); err != nil {
		h.Logger.Error("dcr_store_failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to register client")
		return
	}

	// Build the RFC 7591 response: echo the metadata fields at top level alongside
	// the assigned credentials. Copy the input map first so we don't mutate it.
	resp := make(map[string]any, len(metadata)+4)
	for k, v := range metadata {
		resp[k] = v
	}
	resp["client_id"] = client.ClientID
	resp["client_secret"] = client.ClientSecret
	resp["client_id_issued_at"] = client.CreatedAt.Unix()
	// client_secret never expires in phase 1.
	resp["client_secret_expires_at"] = 0

	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// CIMDHandler serves the Client Identifier Metadata Document at GET /metadata.json.
// CIMD lets non-DCR clients identify themselves with a URL pointing at a stable
// metadata JSON (think: `client_id = https://broker.x-auth.com/metadata.json`).
// The contents mirror a DCR response but describe the broker-hosted "default" client.
type CIMDHandler struct {
	Issuer string
}

// ServeHTTP returns a static example document describing the default X-Auth
// MCP client. Runtimes that support CIMD can point at this URL and get everything
// they need to render a consent screen without a registration round-trip.
func (h *CIMDHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_id":                  h.Issuer + "/metadata.json",
		"client_name":                "X-Auth for Agents",
		"client_uri":                 h.Issuer,
		"logo_uri":                   h.Issuer + "/logo.png",
		"tos_uri":                    h.Issuer + "/tos",
		"policy_uri":                 h.Issuer + "/privacy",
		"redirect_uris":              []string{h.Issuer + "/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      "openid profile mcp",
	})
}
