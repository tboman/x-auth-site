package webauthnx

import "testing"

func TestConfigFromEnvAndNew(t *testing.T) {
	t.Setenv("WAUTHN_RP_ID", "auth.x-auth.com")
	t.Setenv("WAUTHN_RP_DISPLAY_NAME", "X-Auth")
	t.Setenv("WAUTHN_RP_ORIGINS", " https://auth.x-auth.com , https://x-auth.com ")
	t.Setenv("WAUTHN_USER_VERIFICATION", "required")

	cfg := ConfigFromEnv()
	if cfg.RPID != "auth.x-auth.com" {
		t.Fatalf("rp_id = %q", cfg.RPID)
	}
	if len(cfg.RPOrigins) != 2 || cfg.RPOrigins[0] != "https://auth.x-auth.com" || cfg.RPOrigins[1] != "https://x-auth.com" {
		t.Fatalf("origins = %v (should be trimmed/split)", cfg.RPOrigins)
	}

	wa, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if wa.Config.RPID != "auth.x-auth.com" {
		t.Fatalf("wa rp_id = %q", wa.Config.RPID)
	}
	if wa.Config.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("user verification = %q, want required", wa.Config.AuthenticatorSelection.UserVerification)
	}
}

func TestNewFallsBackToLocalhost(t *testing.T) {
	wa, err := New(Config{}, nil) // RPID unset
	if err != nil {
		t.Fatalf("New (unset): %v", err)
	}
	if wa.Config.RPID != "localhost" {
		t.Fatalf("unset rp_id should fall back to localhost, got %q", wa.Config.RPID)
	}
	if wa.Config.AuthenticatorSelection.UserVerification != "preferred" {
		t.Fatalf("default user verification = %q, want preferred", wa.Config.AuthenticatorSelection.UserVerification)
	}
}
