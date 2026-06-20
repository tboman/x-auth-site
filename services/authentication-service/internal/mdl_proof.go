package internal

// mdl_proof.go verifies id-service's Verified Identity Token (the signed proof a
// completed mDL verification produces) so authn can record a user's mDL as an
// identity anchor. The token is an RS256 JWT signed by id-service; authn trusts
// it the same way any relying party would — by validating the signature against
// id-service's published JWKS and checking the audience binds it to this tenant.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/xentranet/x-auth/pkg/jwtx"
)

// mdlProofACR is the acr id-service stamps on an mDL proof token.
const mdlProofACR = "urn:xauth:mdl"

// MDLProof is the trusted content authn extracts from a verified proof token.
type MDLProof struct {
	TrustAnchor   string // signing root (IACA) name — the anchor value we record
	IssuerCN      string // document signer CommonName
	VrfID         string // id-service verification id (audit)
	IssuerTrusted bool   // whether id-service anchored the chain to a configured root
}

// MDLProofVerifier validates an id-service proof token for a tenant.
type MDLProofVerifier interface {
	Verify(ctx context.Context, token, tenantID string) (MDLProof, error)
}

// HTTPMDLProofVerifier validates tokens against id-service's JWKS, fetched lazily
// and cached. On a verification failure it refetches once (key rotation) before
// giving up.
type HTTPMDLProofVerifier struct {
	Issuer  string // expected iss, e.g. https://id.x-auth.com
	JWKSURL string // e.g. https://id.x-auth.com/v1/jwks
	HTTP    *http.Client
	Logger  *slog.Logger

	mu  sync.Mutex
	ver *jwtx.Verifier
}

// NewHTTPMDLProofVerifier builds a verifier. issuer is id-service's ID_ISSUER;
// jwksURL defaults to issuer + "/v1/jwks" when empty. Returns a nil interface
// when issuer is unset (feature disabled — the handler reports "not configured");
// returning the interface type avoids the typed-nil-pointer gotcha.
func NewHTTPMDLProofVerifier(issuer, jwksURL string, logger *slog.Logger) MDLProofVerifier {
	if issuer == "" {
		return nil
	}
	if jwksURL == "" {
		jwksURL = issuer + "/v1/jwks"
	}
	return &HTTPMDLProofVerifier{
		Issuer:  issuer,
		JWKSURL: jwksURL,
		HTTP:    &http.Client{Timeout: defaultClientTimeout},
		Logger:  logger,
	}
}

func (v *HTTPMDLProofVerifier) verifier(ctx context.Context, force bool) (*jwtx.Verifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ver != nil && !force {
		return v.ver, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch id-service jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("id-service jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set jwtx.JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse id-service jwks: %w", err)
	}
	ver, err := jwtx.NewVerifierFromJWKS(v.Issuer, set)
	if err != nil {
		return nil, fmt.Errorf("build id-service verifier: %w", err)
	}
	v.ver = ver
	return ver, nil
}

// ErrMDLProofInvalid is returned for any token that fails validation.
var ErrMDLProofInvalid = errors.New("mdl proof token is invalid")

func (v *HTTPMDLProofVerifier) Verify(ctx context.Context, token, tenantID string) (MDLProof, error) {
	now := time.Now().UTC()
	claims, extra, err := v.verifyWithRefresh(ctx, token, now)
	if err != nil {
		return MDLProof{}, fmt.Errorf("%w: %v", ErrMDLProofInvalid, err)
	}
	// The proof is audience-bound to the tenant it was issued for; refuse to
	// attach a proof minted for another workspace.
	if claims.Aud != tenantID {
		return MDLProof{}, fmt.Errorf("%w: audience %q is not this workspace", ErrMDLProofInvalid, claims.Aud)
	}
	if claims.ACR != mdlProofACR {
		return MDLProof{}, fmt.Errorf("%w: not an mDL proof (acr %q)", ErrMDLProofInvalid, claims.ACR)
	}
	return MDLProof{
		TrustAnchor:   asString(extra["trust_anchor"]),
		IssuerCN:      asString(extra["issuer_cn"]),
		VrfID:         asString(extra["vrf_id"]),
		IssuerTrusted: extra["issuer_trusted"] == true,
	}, nil
}

func (v *HTTPMDLProofVerifier) verifyWithRefresh(ctx context.Context, token string, now time.Time) (jwtx.Claims, map[string]any, error) {
	ver, err := v.verifier(ctx, false)
	if err != nil {
		return jwtx.Claims{}, nil, err
	}
	claims, extra, err := ver.Verify(token, now)
	if err == nil {
		return claims, extra, nil
	}
	// Possible key rotation — refetch the JWKS once and retry.
	ver, ferr := v.verifier(ctx, true)
	if ferr != nil {
		return jwtx.Claims{}, nil, err
	}
	return ver.Verify(token, now)
}
