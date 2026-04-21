package internal

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// GetTransaction handles GET /v1/transactions/{id}.
func (h *Handlers) GetTransaction(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is required")
		return
	}
	t, err := h.Store.Get(tenantID, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "transaction not found")
			return
		}
		h.Logger.Error("txn_get_failed", "err", err, "txn_id", id)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to read transaction")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, t)
}

// ListTransactions handles GET /v1/transactions. Supports:
//   - limit (int, default 100, max 500)
//   - cursor (RFC3339 timestamp; results are strictly older than this)
func (h *Handlers) ListTransactions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := tenantx.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id required")
		return
	}

	q := r.URL.Query()

	limit := DefaultListLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_limit",
				"limit must be a positive integer")
			return
		}
		if n > MaxListLimit {
			n = MaxListLimit
		}
		limit = n
	}

	var cursor time.Time
	if v := q.Get("cursor"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_cursor",
				"cursor must be an RFC3339 timestamp")
			return
		}
		cursor = t
	}

	items, err := h.Store.List(tenantID, limit, cursor)
	if err != nil {
		h.Logger.Error("txn_list_failed", "err", err, "tenant_id", tenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to list transactions")
		return
	}

	resp := ListResponse{Items: items}
	// If we returned a full page, provide a cursor for the next page. Callers that
	// do not need pagination can ignore next_cursor.
	if len(items) == limit && limit > 0 {
		resp.NextCursor = items[len(items)-1].CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
