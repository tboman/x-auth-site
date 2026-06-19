package internal

import (
	"testing"
)

func extDescs(ids ...string) []mdsExtension {
	out := make([]mdsExtension, 0, len(ids))
	for _, id := range ids {
		out = append(out, mdsExtension{ID: id})
	}
	return out
}

func testEntry(aaguid, desc string, kp []string, status string, exts ...string) mdsEntry {
	return mdsEntry{
		AaGUID: aaguid,
		MetadataStatement: mdsStatement{
			Description:         desc,
			ProtocolFamily:      "fido2",
			KeyProtection:       kp,
			AttestationTypes:    []string{"basic_full"},
			SupportedExtensions: extDescs(exts...),
		},
		StatusReports: []mdsStatusReport{
			{Status: status, EffectiveDate: "2022-01-01"},
		},
	}
}

func TestDeriveProfile_HardwareCertified(t *testing.T) {
	e := testEntry("ee882879-721c-4913-9775-3dfcce97072a", "YubiKey 5",
		[]string{"hardware", "secure_element"}, "FIDO_CERTIFIED_L2", "hmac-secret", "largeBlobKey", "credProtect")

	p := deriveProfile(normalizeAAGUID(e.AaGUID), e)

	if p.Binding != BindingHardware || !p.HardwareBound {
		t.Fatalf("binding=%q hardwareBound=%v, want hardware/true", p.Binding, p.HardwareBound)
	}
	if !p.Certification.FidoCertified || p.Certification.Level != "L2" {
		t.Fatalf("certification=%+v, want certified L2", p.Certification)
	}
	if !p.Extensions.PRF || !p.Extensions.LargeBlob || !p.Extensions.CredProtect {
		t.Fatalf("extensions=%+v, want prf+largeBlob+credProtect", p.Extensions)
	}
	if p.RiskTier != TierLow {
		t.Fatalf("riskTier=%q, want low (score %d)", p.RiskTier, p.RiskScore)
	}
}

func TestDeriveProfile_SoftwareNotCertified(t *testing.T) {
	e := testEntry("11111111-2222-3333-4444-555555555555", "Soft Authenticator",
		[]string{"software"}, "NOT_FIDO_CERTIFIED")

	p := deriveProfile(normalizeAAGUID(e.AaGUID), e)

	if p.Binding != BindingSoftware || p.HardwareBound {
		t.Fatalf("binding=%q hardwareBound=%v, want software/false", p.Binding, p.HardwareBound)
	}
	if p.Certification.FidoCertified {
		t.Fatalf("expected not certified, got %+v", p.Certification)
	}
	if p.RiskTier == TierLow {
		t.Fatalf("software + uncertified should not be low risk (score %d)", p.RiskScore)
	}
}

func TestDeriveProfile_RevokedIsHighRisk(t *testing.T) {
	e := testEntry("99999999-0000-0000-0000-000000000000", "Bad Key",
		[]string{"hardware"}, "REVOKED")

	p := deriveProfile(normalizeAAGUID(e.AaGUID), e)

	if len(p.Certification.Advisories) == 0 {
		t.Fatalf("expected an advisory for REVOKED, got %+v", p.Certification)
	}
	if p.RiskTier != TierHigh {
		t.Fatalf("riskTier=%q, want high for revoked authenticator", p.RiskTier)
	}
}

func TestApplyAttestation_BackupEligibleIsSynced(t *testing.T) {
	e := testEntry("22222222-2222-2222-2222-222222222222", "Platform Authenticator",
		[]string{"hardware"}, "FIDO_CERTIFIED_L1")
	p := deriveProfile(normalizeAAGUID(e.AaGUID), e)

	applyAttestation(&p, AttestationFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true})

	if p.Binding != BindingSynced {
		t.Fatalf("binding=%q, want synced after backup-eligible attestation", p.Binding)
	}
	if p.Source != SourceMDSAttestation {
		t.Fatalf("source=%q, want mds+attestation", p.Source)
	}
	if p.Attestation == nil || !p.Attestation.BackupEligible {
		t.Fatalf("attestation flags not attached: %+v", p.Attestation)
	}
}

func TestScoreProfile_NoDuplicateSignals(t *testing.T) {
	e := testEntry("33333333-3333-3333-3333-333333333333", "Key", []string{"hardware"}, "FIDO_CERTIFIED_L2")
	p := deriveProfile(normalizeAAGUID(e.AaGUID), e)
	// Re-score (as applyAttestation would) and ensure owned signals aren't duplicated.
	scoreProfile(&p)

	seen := map[string]int{}
	for _, s := range p.Signals {
		seen[s]++
	}
	for s, n := range seen {
		if n > 1 {
			t.Fatalf("signal %q appeared %d times", s, n)
		}
	}
}
