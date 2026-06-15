package internal

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// advice.go serves POST /v1/advice — a tenant's backend asks what assurance
// (protection) level a transaction requires before it proceeds. The caller
// authenticates as a CONFIDENTIAL OIDC client (client_id + client_secret, HTTP
// Basic or client_secret_post); the tenant is taken from the authenticated
// client. The transaction_type is resolved against the tenant's configured types
// (managed in the owner dashboard) and mapped — for now, directly — to one of the
// eight protection levels.
//
// The session/user/device ids are accepted (and logged) as the subject context a
// real risk evaluation will consume; today they don't change the result. The
// response hands back the level's ACR so the caller can request it at /authorize
// via acr_values.
type AdviceHandlers struct {
	Store  Storage
	Logger *slog.Logger
}

type adviceRequest struct {
	SessionID       string `json:"session_id"`
	UserID          string `json:"user_id"`
	DeviceID        string `json:"device_id"`
	TransactionType string `json:"transaction_type"`
}

// Advise handles POST /v1/advice.
func (h *AdviceHandlers) Advise(w http.ResponseWriter, r *http.Request) {
	// ParseForm populates PostForm for client_secret_post / form callers. It does
	// not consume a JSON body (wrong content type), so the JSON decode below still
	// sees it.
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "could not parse request")
		return
	}

	client, ok := h.authClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="x-auth advice"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "confidential client authentication required")
		return
	}

	var req adviceRequest
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
	} else {
		req.SessionID = r.PostForm.Get("session_id")
		req.UserID = r.PostForm.Get("user_id")
		req.DeviceID = r.PostForm.Get("device_id")
		req.TransactionType = r.PostForm.Get("transaction_type")
	}

	txnType := strings.TrimSpace(req.TransactionType)
	if txnType == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "transaction_type is required")
		return
	}

	tt, err := h.Store.GetTransactionType(client.TenantID, txnType)
	if err == ErrNotFound {
		httpx.WriteError(w, http.StatusNotFound, "unknown_transaction_type",
			"transaction_type is not configured for this tenant")
		return
	}
	if err != nil {
		h.Logger.Error("advice_lookup_failed", "err", err, "tenant_id", client.TenantID)
		httpx.WriteError(w, http.StatusBadGateway, "internal_error", "could not resolve transaction type")
		return
	}

	lvl, ok := protectionByACR(tt.ACR)
	if !ok {
		// A stored mapping no longer matches the ladder (shouldn't happen — the
		// owner form validates the ACR). Fail loud rather than advise blindly.
		h.Logger.Error("advice_invalid_mapping", "acr", tt.ACR, "tenant_id", client.TenantID, "transaction_type", tt.Name)
		httpx.WriteError(w, http.StatusBadGateway, "internal_error", "configured protection level is invalid")
		return
	}

	h.Logger.Info("advice_issued",
		"tenant_id", client.TenantID, "client_id", client.ClientID, "transaction_type", tt.Name,
		"acr", lvl.ACR, "rank", lvl.Rank, "session_id", req.SessionID, "user_id", req.UserID, "device_id", req.DeviceID)

	// Append to the advice history (staff console reads it). Best-effort.
	if err := h.Store.RecordAdviceCall(AdviceCall{
		ID: "adv_" + uuid.NewString(), TenantID: client.TenantID, ClientID: client.ClientID,
		UserID: req.UserID, SessionID: req.SessionID, DeviceID: req.DeviceID,
		TransactionType: tt.Name, ACR: lvl.ACR, Rank: lvl.Rank, CreatedAt: time.Now().UTC(),
	}); err != nil {
		h.Logger.Error("advice_record_failed", "err", err, "tenant_id", client.TenantID)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"tenant_id":        client.TenantID,
		"transaction_type": tt.Name,
		"subject": map[string]string{
			"session_id": req.SessionID,
			"user_id":    req.UserID,
			"device_id":  req.DeviceID,
		},
		"advice": map[string]any{
			"acr":  lvl.ACR,
			"band": lvl.Band,
			"name": lvl.Name,
			"rank": lvl.Rank,
		},
	})
}

// authClient requires a confidential OIDC client: client_id + a secret that
// matches the stored hash (HTTP Basic or client_secret_post). Public clients
// (no stored secret) are rejected — /advice is server-to-server only.
func (h *AdviceHandlers) authClient(r *http.Request) (OIDCClient, bool) {
	clientID, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	if clientID == "" || secret == "" {
		return OIDCClient{}, false
	}
	client, err := h.Store.GetClient(clientID)
	if err != nil || client.ClientSecretHash == "" {
		return OIDCClient{}, false
	}
	if HashToken(secret) != client.ClientSecretHash {
		return OIDCClient{}, false
	}
	return client, true
}
