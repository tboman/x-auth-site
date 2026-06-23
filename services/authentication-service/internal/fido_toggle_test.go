package internal

import (
	"io"
	"log/slog"
	"testing"
)

func newFidoTestHandlers(store Storage) *OIDCHandlers {
	return &OIDCHandlers{
		Store:  store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issuer: "http://test.local",
	}
}

func TestMemCreateTenantDefaultsFidoOn(t *testing.T) {
	store := NewMemStorage()
	tn, err := store.CreateTenant(Tenant{ID: "ten_acme", Slug: "acme", CompanyName: "Acme", OwnerEmail: "o@acme.com"})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if !tn.FidoEnabled {
		t.Fatalf("new tenant should default FidoEnabled=true")
	}
	got, _ := store.GetTenant("ten_acme")
	if !got.FidoEnabled {
		t.Fatalf("stored tenant should be FidoEnabled=true")
	}
}

func TestMemSetTenantOwnerSynthesizesFidoOn(t *testing.T) {
	store := NewMemStorage()
	// A tenant with no prior registry row (staff-assigned / derived) is synthesized.
	if err := store.SetTenantOwner("ten_derived", "owner@x.com"); err != nil {
		t.Fatalf("SetTenantOwner: %v", err)
	}
	got, err := store.GetTenant("ten_derived")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if !got.FidoEnabled {
		t.Fatalf("synthesized tenant should default FidoEnabled=true")
	}
}

func TestTenantFidoEnabledDefaultsOnForUnknown(t *testing.T) {
	h := newFidoTestHandlers(NewMemStorage())
	if !h.tenantFidoEnabled("ten_missing") {
		t.Errorf("unknown tenant should default to FIDO enabled")
	}
	if !h.tenantFidoEnabled("") {
		t.Errorf("empty tenant id should default to FIDO enabled")
	}
}

func TestEffectiveStepUpSpec(t *testing.T) {
	store := NewMemStorage()
	if _, err := store.CreateTenant(Tenant{ID: "ten_on", Slug: "on", CompanyName: "On"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateTenant(Tenant{ID: "ten_off", Slug: "off", CompanyName: "Off"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTenantFidoEnabled("ten_off", false); err != nil {
		t.Fatal(err)
	}
	h := newFidoTestHandlers(store)

	fido, _ := specForMethod(stepUpMethodFIDO2)
	sms, _ := specForMethod(stepUpMethodSMS)

	// FIDO on (default) → fido2 spec unchanged.
	if got := h.effectiveStepUpSpec("ten_on", fido); got.Method != stepUpMethodFIDO2 {
		t.Errorf("FIDO-on tenant: got method %q, want fido2", got.Method)
	}
	// FIDO off → fido2 downgraded to sms.
	if got := h.effectiveStepUpSpec("ten_off", fido); got.Method != stepUpMethodSMS {
		t.Errorf("FIDO-off tenant: got method %q, want sms (fallback)", got.Method)
	}
	// A non-fido spec is never altered, even when FIDO is off.
	if got := h.effectiveStepUpSpec("ten_off", sms); got.Method != stepUpMethodSMS {
		t.Errorf("sms spec should pass through unchanged, got %q", got.Method)
	}
}
