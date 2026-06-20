// Package internal holds the id-service implementation: the remote
// identity-verification flow (W3C Digital Credentials API + OpenID4VP), the ISO
// 18013-5 mdoc (mobile driver's licence) verifier, the pluggable issuer trust
// store, and the HTTP API + the two server-rendered UIs. See
// services/id-service/README.md for the contract.
package internal

import (
	"encoding/json"
	"time"
)

// Verification lifecycle status values.
const (
	StatusPending  = "pending"
	StatusVerified = "verified"
	StatusFailed   = "failed"
	StatusExpired  = "expired"
)

// ISO 18013-5 mobile driving licence identifiers.
const (
	DefaultDocType   = "org.iso.18013.5.1.mDL" // mDL document type
	DefaultNamespace = "org.iso.18013.5.1"     // mDL data-element namespace
)

// Assurance tiers, mirroring the green/amber/red language used across the sites.
const (
	AssuranceHigh   = "high"   // issuer-trusted + device-bound + fresh
	AssuranceMedium = "medium" // device-bound but issuer chain not anchored
	AssuranceLow    = "low"    // structural only (no device binding / untrusted)
)

// VerifyRequestSpec is the POST /v1/verifications body: what the agent wants the
// user to prove. All fields are optional; sensible mDL defaults apply.
type VerifyRequestSpec struct {
	Purpose    string   `json:"purpose,omitempty"`    // shown to the user, e.g. "Authorize wire transfer"
	DocType    string   `json:"docType,omitempty"`    // default org.iso.18013.5.1.mDL
	Claims     []string `json:"claims,omitempty"`     // element ids, e.g. ["family_name","given_name","age_over_21"]
	Channel    string   `json:"channel,omitempty"`    // "portal" (same-device) | "link" (cross-device)
	TTLSeconds int      `json:"ttlSeconds,omitempty"` // pending lifetime override
}

// Verification is the lifecycle record of one identity-proof request. JSON tags
// expose only the agent-facing view; binding material (nonce, token) is omitted.
type Verification struct {
	ID       string   `json:"id"`
	TenantID string   `json:"-"`
	Status   string   `json:"status"`
	Purpose  string   `json:"purpose,omitempty"`
	DocType  string   `json:"docType"`
	Claims   []string `json:"requestedClaims,omitempty"`
	Channel  string   `json:"channel,omitempty"`

	// Protocol binding material (never serialized to the agent view).
	Token       string `json:"-"` // one-time URL token for the consumer page
	Nonce       string `json:"-"` // OpenID4VP nonce; bound into the session transcript
	ClientID    string `json:"-"`
	ResponseURI string `json:"-"`

	VerifyURL string `json:"verifyUrl,omitempty"`

	Result *VerificationResult `json:"result,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// VerificationResult is the verified outcome attached once a wallet response is
// processed. Claims carries the disclosed mDL data elements.
type VerificationResult struct {
	Claims        map[string]any `json:"claims"`
	IssuerTrusted bool           `json:"issuerTrusted"`
	DeviceBound   bool           `json:"deviceBound"`
	IssuerCN      string         `json:"issuerCommonName,omitempty"`
	DocType       string         `json:"docType,omitempty"`
	Assurance     string         `json:"assurance"`
	Signals       []string       `json:"signals,omitempty"`
	ProofToken    string         `json:"proofToken,omitempty"` // signed Verified Identity Token (RS256 JWT)
	ProofJTI      string         `json:"-"`
	FailReason    string         `json:"failReason,omitempty"`
	VerifiedAt    time.Time      `json:"verifiedAt"`
}

// CreateResponse is returned from POST /v1/verifications.
type CreateResponse struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	VerifyURL string    `json:"verifyUrl"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ResponseSubmission is the POST /v1/verifications/{id}/response body. vp_token
// is the OpenID4VP presentation (a base64url DeviceResponse string, or an object
// keyed by credential id). mdoc_generated_nonce is the wallet-chosen nonce that,
// with our nonce, forms the session transcript the device signature is bound to.
type ResponseSubmission struct {
	VPToken            json.RawMessage `json:"vp_token,omitempty"`
	MDocGeneratedNonce string          `json:"mdoc_generated_nonce,omitempty"`
}
