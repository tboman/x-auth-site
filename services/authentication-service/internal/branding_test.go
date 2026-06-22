package internal

import (
	"strings"
	"testing"
)

func TestValidHexColor(t *testing.T) {
	good := []string{"#fff", "#000000", "#00e096", "#AABBCC", "#0a0"}
	for _, s := range good {
		if !validHexColor(s) {
			t.Errorf("validHexColor(%q) = false, want true", s)
		}
	}
	bad := []string{"", "fff", "#ff", "#ffff", "#gggggg", "#00e09", "red", "#00e096;}", "#00e096 "}
	for _, s := range bad {
		if validHexColor(s) {
			t.Errorf("validHexColor(%q) = true, want false", s)
		}
	}
}

func TestValidLogoURL(t *testing.T) {
	good := []string{"https://cdn.example.com/logo.svg", "http://example.com/a.png", "https://x.io"}
	for _, s := range good {
		if !validLogoURL(s) {
			t.Errorf("validLogoURL(%q) = false, want true", s)
		}
	}
	// javascript:/data: and relative URLs must be rejected — they reach an <img src>.
	bad := []string{"", "/logo.svg", "logo.svg", "javascript:alert(1)", "data:image/svg+xml,<svg>", "ftp://host/x", "//evil.com/x"}
	for _, s := range bad {
		if validLogoURL(s) {
			t.Errorf("validLogoURL(%q) = true, want false", s)
		}
	}
}

func TestBrandingCSS(t *testing.T) {
	// Zero value emits nothing — the default theme is untouched.
	if got := brandingCSS(Branding{}); got != "" {
		t.Errorf("brandingCSS(zero) = %q, want empty", got)
	}
	// Accent only → overrides --accent + derives --on-accent, leaves --bg alone.
	css := brandingCSS(Branding{Accent: "#3b82f6"})
	if !strings.Contains(css, "--accent:#3b82f6") || !strings.Contains(css, "--on-accent:") {
		t.Errorf("accent css missing overrides: %q", css)
	}
	if strings.Contains(css, "--bg:") {
		t.Errorf("accent-only css should not set --bg: %q", css)
	}
	// Background → derives panel/text/muted/line.
	css = brandingCSS(Branding{BG: "#101820"})
	for _, want := range []string{"--bg:#101820", "--text:", "--panel:", "--muted:", "--line:"} {
		if !strings.Contains(css, want) {
			t.Errorf("bg css missing %q: %q", want, css)
		}
	}
	// Invalid values are dropped, never injected — no breakout possible.
	if got := brandingCSS(Branding{Accent: "#fff;}</style><script>", BG: "red"}); got != "" {
		t.Errorf("invalid colours should be dropped, got %q", got)
	}
}

func TestBrandLogoHTML(t *testing.T) {
	if got := brandLogoHTML(Branding{}); got != "" {
		t.Errorf("no logo should render empty, got %q", got)
	}
	got := brandLogoHTML(Branding{LogoURL: "https://cdn.example.com/l.svg?a=1&b=2"})
	if !strings.HasPrefix(got, `<img class="brand-logo" src="https://cdn.example.com/l.svg?a=1&amp;b=2"`) {
		t.Errorf("logo html not escaped as expected: %q", got)
	}
	// A rejected URL renders nothing rather than an unsafe <img>.
	if got := brandLogoHTML(Branding{LogoURL: "javascript:alert(1)"}); got != "" {
		t.Errorf("unsafe logo URL should render empty, got %q", got)
	}
}

func TestOnColor(t *testing.T) {
	if onColor("#ffffff") != "#0b0b0d" {
		t.Errorf("light background should get dark text")
	}
	if onColor("#000000") != "#f5f6f8" {
		t.Errorf("dark background should get light text")
	}
}

func TestTenantBranding(t *testing.T) {
	tn := Tenant{BrandLogoURL: "https://x/y.png", BrandColor: "#00e096", BrandBgColor: "#09090b"}
	b := tn.Branding()
	if b.LogoURL != tn.BrandLogoURL || b.Accent != tn.BrandColor || b.BG != tn.BrandBgColor {
		t.Errorf("Branding() mapping mismatch: %+v", b)
	}
	if !b.configured() {
		t.Errorf("configured() = false for a fully set tenant")
	}
	if (Branding{}).configured() {
		t.Errorf("configured() = true for zero value")
	}
}
