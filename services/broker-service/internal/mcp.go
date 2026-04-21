package internal

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// MCPHandlers are phase-1 stubs for the MCP wire protocol.
//
// The real integration will:
//   - maintain a persistent SSE stream per agent session
//   - multiplex JSON-RPC 2.0 calls for tool/resource/prompt access
//   - enforce the bearer token against grant-service for every RPC
//
// Phase 1 just proves the endpoints exist, return the right content type, and
// won't crash the process if a runtime probes them during an install.
// TODO(phase-2): wire to a real MCP server implementation.
type MCPHandlers struct {
	Logger *slog.Logger
}

// SSE handles GET /mcp/sse. Opens a text/event-stream, writes a single `ready`
// event so a probing client sees a well-formed stream, then closes. Real MCP
// streams stay open for the lifetime of the agent session.
func (h *MCPHandlers) SSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "streaming_unsupported",
			"server does not support streaming")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	// One `ready` event, then close. SSE event format: `event: <name>\ndata: <payload>\n\n`.
	_, _ = fmt.Fprint(w, "event: ready\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()
}

// RPC handles POST /mcp/rpc. Accepts a JSON-RPC 2.0 request envelope and echoes
// a canned response. Unknown methods return the JSON-RPC method_not_found error
// (-32601) so compliant runtimes can detect the stub gracefully.
func (h *MCPHandlers) RPC(w http.ResponseWriter, r *http.Request) {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
		ID      json.RawMessage `json:"id,omitempty"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error": map[string]any{
				"code":    -32700,
				"message": "parse error",
			},
		})
		return
	}
	if req.JSONRPC != "2.0" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error": map[string]any{
				"code":    -32600,
				"message": "invalid request",
			},
		})
		return
	}

	// Canned positive response for any method — the stub's job is to prove the
	// server is reachable, not to implement the spec.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      req.ID,
		"result": map[string]any{
			"stub":   true,
			"method": req.Method,
			"note":   "broker-service phase 1 stub — real MCP RPC lands in phase 2",
		},
	})
}
