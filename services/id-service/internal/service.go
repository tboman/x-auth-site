package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

const (
	defaultTTL    = 10 * time.Minute
	maxTTL        = 60 * time.Minute
	proofValidity = 24 * time.Hour
)

// Sentinel outcomes the handlers map to HTTP statuses.
var (
	errConflict = errors.New("verification not pending")
	errExpired  = errors.New("verification expired")
)

// Manager is the id-service application core: it creates verifications, builds
// the OpenID4VP request, and verifies wallet responses, minting a signed
// Verified Identity Token on success.
type Manager struct {
	store  Storage
	trust  *TrustStore
	signer *jwtx.Signer
	cache  *VerificationCache
	logger *slog.Logger
	issuer string
	ttl    time.Duration

	now func() time.Time // overridable in tests
}

func NewManager(store Storage, trust *TrustStore, signer *jwtx.Signer, cache *VerificationCache, issuer string, ttl time.Duration, logger *slog.Logger) *Manager {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Manager{
		store:  store,
		trust:  trust,
		signer: signer,
		cache:  cache,
		logger: logger,
		issuer: issuer,
		ttl:    ttl,
		now:    time.Now,
	}
}

// TrustMode/RootCount surface trust config to handlers/health.
func (mgr *Manager) TrustMode() string { return mgr.trust.Mode() }
func (mgr *Manager) RootCount() int    { return mgr.trust.RootCount() }

// JWKS returns the proof-token verification key set, or an empty set when no
// signer is configured.
func (mgr *Manager) JWKS() jwtx.JWKS {
	if mgr.signer == nil {
		return jwtx.JWKS{Keys: []jwtx.JWK{}}
	}
	return mgr.signer.JWKS()
}

// CreateVerification mints a pending verification + its OpenID4VP binding
// material for the given tenant.
func (mgr *Manager) CreateVerification(ctx context.Context, tenant string, spec VerifyRequestSpec) (*Verification, error) {
	now := mgr.now().UTC()
	ttl := mgr.ttl
	if spec.TTLSeconds > 0 {
		ttl = time.Duration(spec.TTLSeconds) * time.Second
		if ttl > maxTTL {
			ttl = maxTTL
		}
	}
	docType := spec.DocType
	if docType == "" {
		docType = DefaultDocType
	}
	channel := spec.Channel
	if channel == "" {
		channel = "portal"
	}

	id := "vrf_" + randToken(16)
	v := &Verification{
		ID:          id,
		TenantID:    tenant,
		Status:      StatusPending,
		Purpose:     spec.Purpose,
		DocType:     docType,
		Claims:      spec.Claims,
		Channel:     channel,
		Token:       randToken(24),
		Nonce:       randToken(24),
		ClientID:    mgr.issuer, // OpenID4VP client_id (DC API): the verifier origin
		ResponseURI: mgr.issuer + "/v1/verifications/" + id + "/response",
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	v.VerifyURL = mgr.issuer + "/v/" + v.Token

	if err := mgr.store.Create(ctx, v); err != nil {
		return nil, err
	}
	mgr.cache.Put(ctx, v.Token, v.ID)
	return v, nil
}

// Get returns a verification scoped to tenant (cross-tenant reads are 404).
func (mgr *Manager) Get(ctx context.Context, tenant, id string) (*Verification, error) {
	v, err := mgr.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if v.TenantID != tenant {
		return nil, ErrNotFound
	}
	return v, nil
}

// GetByToken resolves the consumer-page token (cache fast-path, store
// authoritative).
func (mgr *Manager) GetByToken(ctx context.Context, token string) (*Verification, error) {
	if id, ok := mgr.cache.Get(ctx, token); ok {
		if v, err := mgr.store.Get(ctx, id); err == nil {
			return v, nil
		}
	}
	return mgr.store.GetByToken(ctx, token)
}

// OID4VPRequest returns the request object for a pending verification token.
func (mgr *Manager) OID4VPRequest(ctx context.Context, token string) (*Verification, map[string]any, error) {
	v, err := mgr.GetByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if v.Status != StatusPending {
		return v, nil, errConflict
	}
	if mgr.now().UTC().After(v.ExpiresAt) {
		return v, nil, errExpired
	}
	return v, buildOID4VPRequest(v), nil
}

// SubmitResponse verifies a wallet's vp_token against the pending verification.
// A cryptographic failure is recorded as a failed verification (status=failed)
// and returned without an API error; only lookup/state problems return errors.
func (mgr *Manager) SubmitResponse(ctx context.Context, id string, sub ResponseSubmission) (*Verification, error) {
	v, err := mgr.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	now := mgr.now().UTC()
	if v.Status != StatusPending {
		return v, errConflict
	}
	if now.After(v.ExpiresAt) {
		v.Status = StatusExpired
		v.UpdatedAt = now
		_ = mgr.store.Update(ctx, v)
		return v, errExpired
	}

	raw, err := extractDeviceResponse(sub.VPToken)
	if err != nil {
		return mgr.fail(ctx, v, "invalid_vp_token: "+err.Error())
	}

	out, err := verifyDeviceResponse(raw, mgr.trust, verifyParams{
		docType:     v.DocType,
		clientID:    v.ClientID,
		responseURI: v.ResponseURI,
		nonce:       v.Nonce,
		mdocNonce:   sub.MDocGeneratedNonce,
		now:         now,
	})
	if err != nil {
		return mgr.fail(ctx, v, err.Error())
	}

	assurance, signals := deriveAssurance(out)
	result := &VerificationResult{
		Claims:        out.claims,
		IssuerTrusted: out.issuerTrusted,
		DeviceBound:   out.deviceBound,
		IssuerCN:      out.issuerCN,
		TrustAnchor:   out.trustAnchor,
		DocType:       out.docType,
		Assurance:     assurance,
		Signals:       signals,
		VerifiedAt:    now,
	}
	if proof, jti, err := mgr.mintProof(v, result, now); err != nil {
		mgr.logger.Error("proof_sign_failed", "err", err, "id", v.ID)
	} else {
		result.ProofToken = proof
		result.ProofJTI = jti
	}

	v.Result = result
	v.Status = StatusVerified
	v.UpdatedAt = now
	if err := mgr.store.Update(ctx, v); err != nil {
		return nil, err
	}
	mgr.logger.Info("verification_verified", "id", v.ID, "assurance", assurance,
		"issuer_trusted", out.issuerTrusted, "device_bound", out.deviceBound)
	return v, nil
}

func (mgr *Manager) fail(ctx context.Context, v *Verification, reason string) (*Verification, error) {
	now := mgr.now().UTC()
	v.Status = StatusFailed
	v.UpdatedAt = now
	v.Result = &VerificationResult{Assurance: AssuranceLow, FailReason: reason, VerifiedAt: now}
	_ = mgr.store.Update(ctx, v)
	mgr.logger.Info("verification_failed", "id", v.ID, "reason", reason)
	return v, nil
}

// mintProof issues the Verified Identity Token: a short-lived RS256 JWT binding
// the verified claims (by hash) to the tenant, for non-repudiable downstream use.
func (mgr *Manager) mintProof(v *Verification, result *VerificationResult, now time.Time) (string, string, error) {
	if mgr.signer == nil {
		return "", "", errors.New("no signer configured")
	}
	jti := "prf_" + randToken(12)
	claims := jwtx.Claims{
		Sub:      "vrf:" + v.ID,
		Iss:      mgr.issuer,
		Aud:      v.TenantID,
		Iat:      now.Unix(),
		Exp:      now.Add(proofValidity).Unix(),
		JTI:      jti,
		TenantID: v.TenantID,
		ACR:      "urn:xauth:mdl",
		AMR:      []string{"mdl"},
	}
	extra := map[string]any{
		"vrf_id":         v.ID,
		"doctype":        result.DocType,
		"assurance":      result.Assurance,
		"issuer_trusted": result.IssuerTrusted,
		"device_bound":   result.DeviceBound,
		"claims_sha256":  claimsDigest(result.Claims),
		"issuer_cn":      result.IssuerCN,
		"trust_anchor":   result.TrustAnchor,
	}
	tok, err := mgr.signer.Sign(claims, extra)
	return tok, jti, err
}

// PurgeExpired removes pending verifications past their TTL.
func (mgr *Manager) PurgeExpired(ctx context.Context) (int, error) {
	return mgr.store.PurgeExpired(ctx, mgr.now().UTC())
}

// extractDeviceResponse pulls the raw mdoc DeviceResponse bytes from a vp_token,
// which may be a base64url string or an object keyed by credential id.
func extractDeviceResponse(vpToken json.RawMessage) ([]byte, error) {
	if len(vpToken) == 0 {
		return nil, errors.New("missing vp_token")
	}
	var s string
	if err := json.Unmarshal(vpToken, &s); err == nil {
		return decodeBase64(s)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(vpToken, &m); err == nil && len(m) > 0 {
		// Prefer the credential id we requested.
		if raw, ok := m["mdl"]; ok {
			if b, err := decodeFromValue(raw); err == nil {
				return b, nil
			}
		}
		for _, raw := range m {
			if b, err := decodeFromValue(raw); err == nil {
				return b, nil
			}
		}
	}
	return nil, errors.New("unrecognized vp_token shape")
}

func decodeFromValue(raw json.RawMessage) ([]byte, error) {
	var vs string
	if err := json.Unmarshal(raw, &vs); err == nil {
		return decodeBase64(vs)
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return decodeBase64(arr[0])
	}
	return nil, errors.New("value is not a base64 string or array")
}

// claimsDigest is a stable SHA-256 over the disclosed claims (encoding/json sorts
// map keys, so the digest is deterministic).
func claimsDigest(claims map[string]any) string {
	b, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
