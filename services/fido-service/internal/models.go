// Package internal holds the fido-service implementation: the FIDO Alliance
// Metadata Service (MDS3) loader, the in-memory AAGUID risk index, and the
// public HTTP API. See services/fido-service/README.md for the contract.
package internal

import "encoding/json"

// Binding classifies how the authenticator's private key is held.
const (
	BindingHardware = "hardware" // key bound to a secure element / TEE
	BindingSynced   = "synced"   // multi-device / cloud credential (passkey)
	BindingSoftware = "software" // software key protection, single device
	BindingUnknown  = "unknown"  // not enough information to classify
)

// Risk tiers, mirroring the green/amber/red language on the marketing site.
const (
	TierLow    = "low"
	TierMedium = "medium"
	TierHigh   = "high"
)

// Source records which inputs produced a RiskProfile.
const (
	SourceMDS            = "mds"
	SourceAttestation    = "attestation"
	SourceMDSAttestation = "mds+attestation"
)

// RiskProfile is the enriched posture returned for an AAGUID or a parsed
// attestation. It folds the FIDO MDS metadata statement and status reports into
// a small, opinionated shape a Relying Party can score against directly.
type RiskProfile struct {
	AAGUID           string            `json:"aaguid"`
	Description      string            `json:"description,omitempty"`
	ProtocolFamily   string            `json:"protocolFamily,omitempty"`
	Binding          string            `json:"binding"`
	HardwareBound    bool              `json:"hardwareBound"`
	KeyProtection    []string          `json:"keyProtection,omitempty"`
	AttachmentHint   []string          `json:"attachmentHint,omitempty"`
	AttestationTypes []string          `json:"attestationTypes,omitempty"`
	Certification    Certification     `json:"certification"`
	Extensions       Extensions        `json:"extensions"`
	Attestation      *AttestationFlags `json:"attestation,omitempty"`
	RiskTier         string            `json:"riskTier"`
	RiskScore        int               `json:"riskScore"` // 0..100, higher = riskier
	Signals          []string          `json:"signals,omitempty"`
	Source           string            `json:"source"`
}

// Certification summarizes the authenticator's FIDO Alliance MDS status reports.
type Certification struct {
	FidoCertified       bool     `json:"fidoCertified"`
	Status              string   `json:"status"`          // latest status, e.g. FIDO_CERTIFIED_L2
	Level               string   `json:"level,omitempty"` // L1, L1plus, L2, ...
	LatestEffectiveDate string   `json:"latestEffectiveDate,omitempty"`
	Advisories          []string `json:"advisories,omitempty"` // REVOKED, USER_VERIFICATION_BYPASS, ...
}

// Extensions reports advanced capability support derived from the metadata
// statement's supportedExtensions and the CTAP2 authenticatorGetInfo.
type Extensions struct {
	LargeBlob    bool     `json:"largeBlob"`
	PRF          bool     `json:"prf"` // WebAuthn PRF, backed by CTAP2 hmac-secret
	CredProtect  bool     `json:"credProtect"`
	CredBlob     bool     `json:"credBlob"`
	MinPinLength bool     `json:"minPinLength"`
	Supported    []string `json:"supported,omitempty"`
}

// AttestationFlags are the authenticator-data flags lifted from a supplied
// attestation. BackupEligible is the authoritative synced-credential signal.
type AttestationFlags struct {
	UserPresent            bool `json:"userPresent"`
	UserVerified           bool `json:"userVerified"`
	BackupEligible         bool `json:"backupEligible"`
	BackupState            bool `json:"backupState"`
	AttestedCredentialData bool `json:"attestedCredentialData"`
}

// AttestationRequest is the POST /v1/attestation body. Supply either a bare
// attestationObject (base64url or base64) or a full WebAuthn registration
// response object under "credential".
type AttestationRequest struct {
	AttestationObject string          `json:"attestationObject,omitempty"`
	Credential        json.RawMessage `json:"credential,omitempty"`
}

// MDSStatus is the GET /v1/mds/status response: snapshot freshness and the last
// refresh outcome. It doubles as a deep health probe.
type MDSStatus struct {
	Loaded      bool   `json:"loaded"`
	BlobNumber  int    `json:"blobNumber"`
	EntryCount  int    `json:"entryCount"`
	NextUpdate  string `json:"nextUpdate,omitempty"`
	FetchedAt   string `json:"fetchedAt,omitempty"`
	Source      string `json:"source,omitempty"` // network | cache | store
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt string `json:"lastErrorAt,omitempty"`
}

// ListResponse is the GET /v1/authenticators page envelope.
type ListResponse struct {
	Total    int           `json:"total"`
	Count    int           `json:"count"`
	Offset   int           `json:"offset"`
	Profiles []RiskProfile `json:"profiles"`
}
