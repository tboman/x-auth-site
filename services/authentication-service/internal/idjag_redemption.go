package internal

// idjag_redemption.go is the consumption half of Cross-App Access: X-Auth acting
// as the RESOURCE authorization server that redeems an ID-JAG identity assertion
// for one of its own access tokens (draft-ietf-oauth-identity-assertion-authz-grant
// §6-7; issuance — X-Auth as the IdP — lives in idjag.go).
//
// End-to-end flow (mirror image of idjag.go's):
//
//  1. A requesting app obtained an ID-JAG from its IdP — X-Auth itself or any
//     external provider that speaks the standard (e.g. Okta Cross App Access) —
//     with aud = THIS server's issuer identifier.
//  2. It presents the assertion at the token endpoint with the RFC 7523
//     jwt-bearer grant (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer,
//     assertion=<ID-JAG>), identifying itself as a client registered here.
//  3. This server checks tenant policy — the assertion's issuer must be on the
//     client's tenant [TrustedIDP] registry AND enabled — verifies the JWT
//     against the IdP's published JWKS, enforces the draft's MUSTs (typ header,
//     aud = our issuer, client_id binding, single-use jti), and applies the
//     registry's scope cap.
//  4. It answers with a standard Bearer access token. Per the draft the ID-JAG
//     replaces the refresh token, so none is returned — the app exchanges a
//     fresh assertion when the access token expires.
//
// Discovery advertises the capability via grant_types_supported (jwt-bearer)
// and authorization_grant_profiles_supported (the id-jag grant profile).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
)

const (
	// GrantTypeJWTBearer is the RFC 7523 grant an ID-JAG is redeemed through.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// IDJAGGrantProfile is the authorization_grant_profiles_supported value a
	// resource authorization server advertises when its jwt-bearer grant accepts
	// ID-JAG assertions (draft-ietf-oauth-identity-assertion-authz-grant §7).
	IDJAGGrantProfile = "urn:ietf:params:oauth:grant-profile:id-jag"
)

// handleJWTBearerGrant implements the RFC 7523 jwt-bearer grant for Cross-App
// Access redemption: it validates a presented ID-JAG identity assertion against
// the requesting client's tenant [TrustedIDP] registry and mints a standard
// Bearer access token scoped by that registry's policy.
//
// Errors follow RFC 6749 codes: invalid_request (malformed), invalid_client
// (client authentication failed / no client identified), invalid_grant (the
// assertion fails any of the draft's MUSTs — untrusted issuer, bad signature,
// wrong typ or aud, client mismatch, replayed jti), invalid_scope (a narrowing
// scope parameter asks for more than the assertion carries). Dispatched from
// Token() on GrantTypeJWTBearer.
func (h *OIDCHandlers) handleJWTBearerGrant(w http.ResponseWriter, r *http.Request) {
	assertion := r.PostForm.Get("assertion")
	if assertion == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "assertion is required")
		return
	}
	// The JOSE typ MUST be the ID-JAG media type (§6.1) — an access or ID token
	// (typ JWT) is not an authorization grant and must not be redeemable as one.
	if typ, err := jwtType(assertion); err != nil || typ != IDJAGTypeHeader {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant",
			"assertion must be an ID-JAG identity assertion (typ "+IDJAGTypeHeader+")")
		return
	}

	// The requesting app must be a client registered with THIS server: the
	// draft's client_id binding check needs an identified client, and the
	// client's tenant selects which TrustedIDP registry applies.
	clientID, _, ok := h.extractClientCreds(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if clientID == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client",
			"client_id is required for the jwt-bearer grant")
		return
	}
	client, err := h.Store.GetClient(clientID)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_client", "client is not registered")
		return
	}
	if client.TenantID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant",
			"client is not bound to a workspace — no trusted-IdP policy applies")
		return
	}

	// Tenant policy gate BEFORE any crypto: the assertion's issuer must be on
	// the tenant's trusted-IdP registry and enabled. The issuer is read from
	// the (unverified) payload only to select the key set — nothing is trusted
	// until the signature verifies against that issuer's published JWKS.
	iss, err := jwtIssuer(assertion)
	if err != nil || iss == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion is missing an issuer")
		return
	}
	idp, ok := h.trustedIDP(client.TenantID, iss)
	if !ok {
		h.Logger.Warn("idjag_issuer_not_trusted", "tenant_id", client.TenantID, "issuer", iss, "client_id", clientID)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant",
			"assertion issuer is not a trusted identity provider for this workspace")
		return
	}

	claims, raw, err := h.IDPVerifiers.Verify(r.Context(), idp.Issuer, idp.JWKSURI, assertion, time.Now().UTC())
	if err != nil {
		h.Logger.Warn("idjag_verify_failed", "err", err, "tenant_id", client.TenantID, "issuer", iss)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion signature or claims invalid")
		return
	}
	// aud MUST be this server's issuer identifier (§6.1) — an assertion minted
	// for another resource must not be redeemable here.
	if claims.Aud != h.JWTIssuer {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant",
			"assertion audience must be this authorization server's issuer identifier")
		return
	}
	// client_id MUST identify the same client as the request's authentication
	// (§6.1) — blocks one app from redeeming another app's assertion.
	if assertClient, _ := raw["client_id"].(string); assertClient != clientID {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion was issued to a different client")
		return
	}
	if claims.Sub == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion is missing a subject")
		return
	}
	// Single use: the jti is burned on redemption; a second presentation is a
	// replay. The record only needs to live until the assertion expires.
	if claims.JTI == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion is missing a jti")
		return
	}
	switch err := h.Store.RedeemIDJAGJTI(claims.JTI, time.Unix(claims.Exp, 0).UTC()); {
	case errors.Is(err, ErrConflict):
		h.Logger.Warn("idjag_replay", "tenant_id", client.TenantID, "issuer", iss, "jti", claims.JTI)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "assertion has already been redeemed")
		return
	case err != nil:
		h.Logger.Error("idjag_jti_store_failed", "err", err, "tenant_id", client.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to record assertion redemption")
		return
	}

	// Scope: start from what the assertion carries; a scope parameter may only
	// narrow it (excess is invalid_scope); the registry's cap then narrows
	// further — local policy MAY reduce what the IdP granted (§6.1), and the
	// response's scope field reports the result.
	granted := strings.Fields(claims.Scope)
	if requested := strings.Fields(r.PostForm.Get("scope")); len(requested) > 0 {
		// Unlike issuance's empty-allow-list-means-all, a scopeless assertion
		// grants NOTHING extra — so the subset check must run against the
		// assertion's actual scopes, never fall open.
		narrowed, ok := grantedScopes(granted, requested)
		if !ok || len(granted) == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds what the assertion grants")
			return
		}
		granted = narrowed
	}
	if len(idp.Scopes) > 0 {
		granted = intersectScopes(granted, idp.Scopes)
	}
	scope := strings.Join(granted, " ")

	// Mint the access token through the standard shape: a session gives the
	// token the usual revocation surface (owner dashboard, /revoke deny list).
	// The subject lives in the ISSUING IdP's namespace — it may have no local
	// user row, which is fine: the token authorizes resource APIs, and
	// /userinfo simply rejects a subject it cannot resolve.
	now := time.Now().UTC()
	sess := Session{
		ID:        "ses_" + uuid.NewString(),
		TenantID:  client.TenantID,
		UserID:    claims.Sub,
		RiskLevel: RiskLow,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Duration(SessionTTLSeconds) * time.Second),
	}
	if _, err := h.Store.CreateSession(sess); err != nil {
		h.Logger.Error("idjag_session_create_failed", "err", err, "tenant_id", client.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue session")
		return
	}
	accessExpiry := now.Add(time.Duration(AccessTokenTTLSeconds) * time.Second)
	accessPlain, err := h.Signer.Sign(jwtx.Claims{
		Sub:       claims.Sub,
		Iss:       h.JWTIssuer,
		Aud:       clientID,
		Exp:       accessExpiry.Unix(),
		Iat:       now.Unix(),
		JTI:       uuid.NewString(),
		TenantID:  client.TenantID,
		Scope:     scope,
		SessionID: sess.ID,
	}, nil)
	if err != nil {
		h.Logger.Error("idjag_redeem_sign_failed", "err", err, "tenant_id", client.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue access token")
		return
	}
	if err := h.Store.PutToken(Token{
		TokenHash: HashToken(accessPlain),
		SessionID: sess.ID,
		UserID:    claims.Sub,
		TenantID:  client.TenantID,
		ClientID:  clientID,
		FamilyID:  "fam_" + uuid.NewString(),
		TokenType: TokenTypeAccess,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: accessExpiry,
	}); err != nil {
		h.Logger.Error("idjag_redeem_store_failed", "err", err, "tenant_id", client.TenantID)
		httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "failed to issue access token")
		return
	}

	h.Logger.Info("idjag_redeemed", "tenant_id", client.TenantID, "user_id", claims.Sub,
		"client_id", clientID, "issuer", idp.Issuer, "scope", scope, "jti", claims.JTI)

	// No refresh_token: the draft says the ID-JAG replaces it — the app comes
	// back with a fresh assertion instead (§6.2).
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": accessPlain,
		"token_type":   "Bearer",
		"expires_in":   AccessTokenTTLSeconds,
		"scope":        scope,
	})
}

// trustedIDP returns the tenant's enabled trusted-IdP registry entry whose
// Issuer exactly matches iss, and whether one was found. A disabled entry is
// treated as not found — redemption must respect the toggle.
func (h *OIDCHandlers) trustedIDP(tenantID, iss string) (TrustedIDP, bool) {
	idps, err := h.Store.ListTrustedIDPs(tenantID)
	if err != nil {
		h.Logger.Error("idjag_list_idps_failed", "err", err, "tenant_id", tenantID)
		return TrustedIDP{}, false
	}
	for _, p := range idps {
		if p.Issuer == iss && p.Enabled {
			return p, true
		}
	}
	return TrustedIDP{}, false
}

// intersectScopes returns the members of scopes also present in allowed,
// preserving order — the registry cap narrowing the assertion's grant.
func intersectScopes(scopes, allowed []string) []string {
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allow[s] = struct{}{}
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if _, ok := allow[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// jwtIssuer returns the iss claim from a compact JWT's payload WITHOUT
// verifying the signature — used only to select which trusted IdP's key set
// the real verification runs against.
func jwtIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var p struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", err
	}
	return p.Iss, nil
}

// IDPVerifierCache verifies tokens against external IdPs' published JWKS
// documents, fetched lazily over HTTPS and cached per issuer. On a verification
// failure it refetches once (key rotation) before giving up — the same pattern
// HTTPMDLProofVerifier uses for id-service proofs.
type IDPVerifierCache struct {
	HTTP   *http.Client
	Logger *slog.Logger

	mu   sync.Mutex
	vers map[string]*jwtx.Verifier // keyed by issuer + "\x00" + jwksURI
}

// NewIDPVerifierCache builds the cache used by the jwt-bearer grant.
func NewIDPVerifierCache(logger *slog.Logger) *IDPVerifierCache {
	return &IDPVerifierCache{
		HTTP:   &http.Client{Timeout: defaultClientTimeout},
		Logger: logger,
		vers:   make(map[string]*jwtx.Verifier),
	}
}

// Verify validates token against the JWKS the issuer publishes at jwksURI,
// enforcing iss/exp/iat/signature via jwtx. A failure after a fresh JWKS fetch
// is final.
func (c *IDPVerifierCache) Verify(ctx context.Context, issuer, jwksURI, token string, now time.Time) (jwtx.Claims, map[string]any, error) {
	ver, err := c.verifier(ctx, issuer, jwksURI, false)
	if err != nil {
		return jwtx.Claims{}, nil, err
	}
	claims, raw, err := ver.Verify(token, now)
	if err == nil {
		return claims, raw, nil
	}
	// Possible key rotation — refetch the JWKS once and retry.
	ver, ferr := c.verifier(ctx, issuer, jwksURI, true)
	if ferr != nil {
		return jwtx.Claims{}, nil, err
	}
	return ver.Verify(token, now)
}

func (c *IDPVerifierCache) verifier(ctx context.Context, issuer, jwksURI string, force bool) (*jwtx.Verifier, error) {
	key := issuer + "\x00" + jwksURI
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.vers[key]; ok && !force {
		return v, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch idp jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("idp jwks %s: status %d", jwksURI, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set jwtx.JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse idp jwks: %w", err)
	}
	ver, err := jwtx.NewVerifierFromJWKS(issuer, set)
	if err != nil {
		return nil, fmt.Errorf("build idp verifier: %w", err)
	}
	c.vers[key] = ver
	return ver, nil
}
