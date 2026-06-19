package internal

import (
	"sort"
	"strings"

	"github.com/go-webauthn/webauthn/metadata"
)

// deriveProfile folds a single MDS entry into a RiskProfile. It is the MDS-only
// view; attestation flags (when a payload is supplied) are layered on top by
// applyAttestation.
func deriveProfile(aaguid string, e mdsEntry) RiskProfile {
	ms := e.MetadataStatement

	p := RiskProfile{
		AAGUID:           aaguid,
		Description:      ms.Description,
		ProtocolFamily:   ms.ProtocolFamily,
		KeyProtection:    ms.KeyProtection,
		AttachmentHint:   ms.AttachmentHint,
		AttestationTypes: ms.AttestationTypes,
		Extensions:       deriveExtensions(ms),
		Certification:    deriveCertification(e.StatusReports),
		Source:           SourceMDS,
	}

	hardware := containsAny(ms.KeyProtection, "hardware", "secure_element", "tee")
	softwareOnly := contains(ms.KeyProtection, "software") && !hardware
	switch {
	case hardware:
		p.Binding = BindingHardware
		p.HardwareBound = true
	case softwareOnly:
		p.Binding = BindingSoftware
	default:
		p.Binding = BindingUnknown
	}

	scoreProfile(&p)
	return p
}

// unknownProfile is the base used when an attestation carries an AAGUID absent
// from the MDS snapshot. Binding/score are filled in by applyAttestation.
func unknownProfile(aaguid string) RiskProfile {
	p := RiskProfile{
		AAGUID:        aaguid,
		Binding:       BindingUnknown,
		Certification: Certification{Status: "unknown"},
		Source:        SourceMDS,
		Signals:       []string{"AAGUID not found in FIDO Alliance MDS"},
		RiskScore:     45,
		RiskTier:      TierMedium,
	}
	return p
}

// applyAttestation layers authenticator-data flags onto a profile. BackupEligible
// is authoritative for the synced/multi-device classification.
func applyAttestation(p *RiskProfile, f AttestationFlags) {
	p.Attestation = &f
	if p.Source == SourceMDS {
		p.Source = SourceMDSAttestation
	} else {
		p.Source = SourceAttestation
	}
	if f.BackupEligible {
		p.Binding = BindingSynced
		p.HardwareBound = false
		p.Signals = append(p.Signals, "credential is backup-eligible (synced / multi-device)")
	}
	if !f.UserVerified {
		p.Signals = append(p.Signals, "user verification not performed on this ceremony")
	}
	scoreProfile(p)
}

// scoreProfile (re)computes RiskScore/RiskTier and the binding/cert signals from
// the profile's current fields. It is idempotent: signals it owns are rebuilt
// each call, attestation-supplied signals are preserved.
func scoreProfile(p *RiskProfile) {
	// Preserve signals not owned by the scorer (attestation notes, MDS-miss note).
	var kept []string
	for _, s := range p.Signals {
		if !ownedSignal(s) {
			kept = append(kept, s)
		}
	}

	score := 35 // medium baseline
	var signals []string

	switch p.Binding {
	case BindingHardware:
		score -= 20
		signals = append(signals, "hardware-bound key protection")
	case BindingSynced:
		score += 15
		signals = append(signals, "synced / multi-device credential")
	case BindingSoftware:
		score += 10
		signals = append(signals, "software key protection (no hardware binding)")
	default:
		score += 5
	}

	if p.Certification.FidoCertified {
		score -= 10
		signals = append(signals, "FIDO certified ("+p.Certification.Status+")")
		switch p.Certification.Level {
		case "L2", "L2plus", "L3", "L3plus":
			score -= 5
		}
	} else if p.Certification.Status != "" && p.Certification.Status != "unknown" {
		score += 10
		signals = append(signals, "not FIDO certified ("+p.Certification.Status+")")
	}

	advisory := len(p.Certification.Advisories) > 0
	if advisory {
		score += 45
		signals = append(signals, "security advisory: "+strings.Join(p.Certification.Advisories, ", "))
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	p.RiskScore = score

	switch {
	case advisory || score >= 60:
		p.RiskTier = TierHigh
	case score >= 30:
		p.RiskTier = TierMedium
	default:
		p.RiskTier = TierLow
	}

	p.Signals = append(signals, kept...)
}

// ownedSignal reports whether a signal string is one scoreProfile regenerates,
// so re-scoring doesn't duplicate it.
func ownedSignal(s string) bool {
	for _, pfx := range []string{
		"hardware-bound", "synced / multi-device", "software key protection",
		"FIDO certified", "not FIDO certified", "security advisory:",
	} {
		if strings.HasPrefix(s, pfx) {
			return true
		}
	}
	return false
}

func deriveExtensions(ms mdsStatement) Extensions {
	ids := map[string]bool{}
	for _, e := range ms.SupportedExtensions {
		if e.ID != "" {
			ids[e.ID] = true
		}
	}
	for _, e := range ms.AuthenticatorGetInfo.Extensions {
		if e != "" {
			ids[e] = true
		}
	}
	opt := ms.AuthenticatorGetInfo.Options

	ext := Extensions{
		LargeBlob:    ids["largeBlobKey"] || opt["largeBlobs"],
		PRF:          ids["hmac-secret"],
		CredProtect:  ids["credProtect"],
		CredBlob:     ids["credBlob"],
		MinPinLength: ids["minPinLength"] || opt["setMinPINLength"],
	}
	for id := range ids {
		ext.Supported = append(ext.Supported, id)
	}
	sort.Strings(ext.Supported)
	return ext
}

// deriveCertification reduces the status-report history to the current
// certification posture. Reports are chronological, so the last FIDO_CERTIFIED*
// wins; any undesired status (revoked / compromise / UV bypass) becomes an
// advisory that forces the high tier.
func deriveCertification(reports []mdsStatusReport) Certification {
	var c Certification
	for _, r := range reports {
		s := r.Status
		if metadata.IsUndesiredAuthenticatorStatus(metadata.AuthenticatorStatus(s)) {
			c.Advisories = append(c.Advisories, s)
			continue
		}
		switch {
		case strings.HasPrefix(s, "FIDO_CERTIFIED"):
			c.Status = s
			c.Level = strings.TrimPrefix(s, "FIDO_CERTIFIED_")
			if c.Level == s { // bare "FIDO_CERTIFIED", no level suffix
				c.Level = "L1"
			}
			if r.EffectiveDate != "" {
				c.LatestEffectiveDate = r.EffectiveDate
			}
		case s == "NOT_FIDO_CERTIFIED" && c.Status == "":
			c.Status = s
		}
	}
	c.FidoCertified = strings.HasPrefix(c.Status, "FIDO_CERTIFIED")
	return c
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

func containsAny(haystack []string, needles ...string) bool {
	for _, n := range needles {
		if contains(haystack, n) {
			return true
		}
	}
	return false
}
