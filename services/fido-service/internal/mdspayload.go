package internal

// Lean MDS payload structs used for parsing the verified blob.
//
// We deliberately do NOT decode into go-webauthn's metadata.MetadataBLOBPayload:
// its MetadataStatement types several fields with tight integer widths (e.g.
// PatternAccuracyDescriptor.minComplexity as uint32) that the production blob
// overflows (a real value of 2^35 has shipped), which makes a strict
// json.Unmarshal fail. These structs carry only the fields the risk engine
// consumes, so the problematic subtrees (userVerificationDetails, etc.) are
// simply ignored. We still reuse metadata.IsUndesiredAuthenticatorStatus for the
// advisory set — see risk.go.

type mdsPayload struct {
	Number     int        `json:"no"`
	NextUpdate string     `json:"nextUpdate"`
	Entries    []mdsEntry `json:"entries"`
}

type mdsEntry struct {
	AaGUID            string            `json:"aaguid"`
	MetadataStatement mdsStatement      `json:"metadataStatement"`
	StatusReports     []mdsStatusReport `json:"statusReports"`
}

type mdsStatusReport struct {
	Status        string `json:"status"`
	EffectiveDate string `json:"effectiveDate"`
}

type mdsStatement struct {
	Description          string         `json:"description"`
	ProtocolFamily       string         `json:"protocolFamily"`
	KeyProtection        []string       `json:"keyProtection"`
	AttachmentHint       []string       `json:"attachmentHint"`
	AttestationTypes     []string       `json:"attestationTypes"`
	SupportedExtensions  []mdsExtension `json:"supportedExtensions"`
	AuthenticatorGetInfo mdsGetInfo     `json:"authenticatorGetInfo"`
}

type mdsExtension struct {
	ID string `json:"id"`
}

type mdsGetInfo struct {
	Extensions []string        `json:"extensions"`
	Options    map[string]bool `json:"options"`
}
