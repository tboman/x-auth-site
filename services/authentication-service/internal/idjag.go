package internal

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

// idjag.go anchors X-Auth's Cross-App Access (XAA) support, built on the IETF
// "Identity Assertion Authorization Grant" (ID-JAG) draft
// (draft-parecki-oauth-identity-assertion-authz-grant) — the same mechanism
// Okta ships as Cross App Access.
//
// End-to-end flow:
//
//  1. A requesting app (e.g. an agent / MCP client) holds a user session at the
//     IdP (X-Auth) — concretely, an access (or ID) token we issued it.
//  2. It calls the token endpoint with RFC 8693 token exchange
//     (grant_type=urn:ietf:params:oauth:grant-type:token-exchange), presenting
//     that token as the subject_token and asking for a requested_token_type of
//     ID-JAG (TokenTypeIDJAG) scoped to a target resource — an MCP server's
//     resource URI / audience (the `resource` or `audience` parameter).
//  3. The IdP checks tenant policy — the resource must be on the tenant's
//     authorized MCP-server list ([MCPServer] registry) AND enabled — downscopes
//     the request against the server's authorized scopes, and mints a signed,
//     short-lived ID-JAG identity assertion (handleTokenExchange).
//  4. The requesting app presents the ID-JAG to the resource's authorization
//     server as a JWT authorization grant to obtain an access token.
//
// Discovery advertises the token-exchange grant (supportedGrantTypes) so
// requesting apps can detect support.

const (
	// GrantTypeTokenExchange is the RFC 8693 token-exchange grant the ID-JAG
	// issuance flow rides on. Advertised in the discovery documents.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeIDJAG is the requested_token_type a requesting app asks for to
	// receive an Identity Assertion Authorization Grant (ID-JAG), and the
	// issued_token_type echoed back on success.
	TokenTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"
	// TokenTypeAccessToken / TokenTypeIDToken are the RFC 8693 subject_token_type
	// values we accept: an access (or ID) token THIS IdP previously issued the
	// requesting app. Both are RS256 JWTs verifiable against our own JWKS.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"

	// IDJAGTypeHeader is the JOSE `typ` an ID-JAG carries so a resource server can
	// distinguish an identity assertion from an ordinary access token
	// (draft-parecki-oauth-identity-assertion-authz-grant §5).
	IDJAGTypeHeader = "oauth-id-jag+jwt"
	// IDJAGTTLSeconds is the ID-JAG lifetime. Assertions are single-hop, redeemed
	// immediately at the resource's token endpoint, so the window is deliberately
	// short to limit replay exposure.
	IDJAGTTLSeconds = 300
)

// supportedGrantTypes is the grant_types_supported list advertised by both
// discovery documents. Token exchange carries the XAA/ID-JAG capability.
func supportedGrantTypes() []string {
	return []string{"authorization_code", "refresh_token", GrantTypeTokenExchange}
}

// handleTokenExchange implements RFC 8693 token exchange for Cross-App Access:
// it converts a subject token (an access/ID token THIS IdP issued the requesting
// app) into a short-lived ID-JAG identity assertion scoped to a target MCP
// server, after checking the resource is on the tenant's authorized allow-list.
//
// Errors follow RFC 8693 / RFC 6749 codes: invalid_request (malformed),
// invalid_grant (unusable subject token), invalid_target (resource not on the
// enabled allow-list), invalid_scope (requested scope exceeds what the tenant
// authorized for the server). Dispatched from Token() on GrantTypeTokenExchange.
func (h *OIDCHandlers) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	requested := r.PostForm.Get("requested_token_type")
	if requested != TokenTypeIDJAG {
		// This service's token-exchange surface mints ID-JAGs only.
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"requested_token_type must be "+TokenTypeIDJAG)
		return
	}
	subjectToken := r.PostForm.Get("subject_token")
	subjectType := r.PostForm.Get("subject_token_type")
	if subjectToken == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	if subjectType != TokenTypeAccessToken && subjectType != TokenTypeIDToken {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"subject_token_type must be an access_token or id_token issued by this server")
		return
	}

	// The target resource is the MCP server's audience. RFC 8693 allows either
	// `resource` (a URI) or `audience` (a logical name); we accept both and
	// require an absolute URL — it must match a registered resource_uri exactly.
	target := r.PostForm.Get("resource")
	if target == "" {
		target = r.PostForm.Get("audience")
	}
	if target == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request",
			"resource (or audience) is required — the target MCP server")
		return
	}
	if u, err := url.Parse(target); err != nil || !u.IsAbs() {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "resource must be an absolute URI")
		return
	}

	// Verify the subject token is one WE issued and still valid: RS256 signature +
	// issuer + time window (same path /userinfo uses). The claims give us the
	// tenant, the end user (sub), and the requesting app (aud).
	claims, _, err := h.Verifier.Verify(subjectToken, time.Now().UTC())
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "subject_token is not a valid token issued by this server")
		return
	}
	if claims.TenantID == "" || claims.Sub == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "subject_token is missing tenant or subject")
		return
	}
	// An access token is revocable; honour the deny list so a revoked session
	// cannot still mint assertions. (ID tokens are not persisted — proof of
	// authentication only — so the signature/time check above is the bound.)
	if subjectType == TokenTypeAccessToken {
		tok, err := h.Store.GetTokenByHash(HashToken(subjectToken))
		if err != nil || tok.TokenType != TokenTypeAccess {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "subject_token is unknown")
			return
		}
		if tok.RevokedAt != nil || time.Now().UTC().After(tok.ExpiresAt) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "subject_token revoked or expired")
			return
		}
	}

	// Optional client authentication. A confidential client that authenticates
	// must be the same app the subject token was issued to (aud) — this blocks one
	// client from exchanging another client's token (token substitution).
	requestingClient := claims.Aud
	if authClient, _, ok := h.extractClientCreds(r); !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	} else if authClient != "" && requestingClient != "" && authClient != requestingClient {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "subject_token was issued to a different client")
		return
	}

	// Tenant policy: the resource must be on this tenant's authorized MCP-server
	// allow-list AND enabled. A disabled or unlisted resource is invalid_target.
	server, ok := h.authorizedMCPServer(claims.TenantID, target)
	if !ok {
		h.Logger.Warn("idjag_target_not_authorized", "tenant_id", claims.TenantID, "resource", target, "client_id", requestingClient)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_target", "resource is not an authorized, enabled MCP server for this tenant")
		return
	}

	// Downscope: requested scope must be a subset of what the tenant authorized
	// for the server. An empty server scope list means "all" (no restriction); an
	// empty request inherits the server's full authorized set.
	granted, ok := grantedScopes(server.Scopes, strings.Fields(r.PostForm.Get("scope")))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds what is authorized for this MCP server")
		return
	}

	now := time.Now().UTC()
	assertion, err := h.Signer.SignTyped(jwtx.Claims{
		Sub:      claims.Sub,
		Iss:      h.JWTIssuer,
		Aud:      server.ResourceURI,
		Exp:      now.Add(IDJAGTTLSeconds * time.Second).Unix(),
		Iat:      now.Unix(),
		JTI:      uuid.NewString(),
		TenantID: claims.TenantID,
		Scope:    strings.Join(granted, " "),
	}, map[string]any{
		// The requesting app is named so the resource's AS can apply per-client
		// policy; it is NOT the audience (that is the resource).
		"client_id": requestingClient,
	}, IDJAGTypeHeader)
	if err != nil {
		h.Logger.Error("idjag_sign_failed", "err", err, "tenant_id", claims.TenantID, "resource", target)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to mint identity assertion")
		return
	}

	h.Logger.Info("idjag_issued", "tenant_id", claims.TenantID, "user_id", claims.Sub,
		"client_id", requestingClient, "resource", server.ResourceURI, "scope", strings.Join(granted, " "))

	// RFC 8693 §2.2.1 success response. token_type is "N_A": the ID-JAG is not a
	// bearer access token, it is a grant the app presents to the resource's AS.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issued_token_type": TokenTypeIDJAG,
		"access_token":      assertion,
		"token_type":        "N_A",
		"expires_in":        IDJAGTTLSeconds,
		"scope":             strings.Join(granted, " "),
	})
}

// authorizedMCPServer returns the tenant's enabled MCP-server registry entry
// whose ResourceURI exactly matches target, and whether one was found. A
// disabled entry is treated as not found — issuance must respect the toggle.
func (h *OIDCHandlers) authorizedMCPServer(tenantID, target string) (MCPServer, bool) {
	servers, err := h.Store.ListMCPServers(tenantID)
	if err != nil {
		h.Logger.Error("idjag_list_mcp_failed", "err", err, "tenant_id", tenantID)
		return MCPServer{}, false
	}
	for _, m := range servers {
		if m.ResourceURI == target && m.Enabled {
			return m, true
		}
	}
	return MCPServer{}, false
}

// grantedScopes resolves the scopes to stamp on the ID-JAG. authorized is the
// tenant's allow-list for the server (empty = unrestricted); requested is the
// caller's ask (empty = take the full authorized set). It returns the granted
// scopes and false when a requested scope is not authorized.
func grantedScopes(authorized, requested []string) ([]string, bool) {
	if len(authorized) == 0 {
		// No per-server restriction configured: grant exactly what was asked.
		return requested, true
	}
	if len(requested) == 0 {
		return authorized, true
	}
	allow := make(map[string]struct{}, len(authorized))
	for _, s := range authorized {
		allow[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allow[s]; !ok {
			return nil, false
		}
	}
	return requested, true
}
