package internal

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// branding.go renders a tenant's per-workspace customisation onto the hosted,
// end-user-facing pages: the /login chooser (login_console.go), phone login
// (phone_login.go), and the step-up verification screens (otp.go,
// webauthn_stepup.go). A workspace owner sets a logo and an accent + background
// colour from their dashboard (signup_console.go "Branding" tab); the values
// live on the tenant row (migration 000019).
//
// Those pages all build their layout from a shared set of CSS custom properties
// in :root (--bg, --panel, --text, --muted, --line, --accent, --on-accent).
// Branding works purely by emitting a second <style> block that redefines those
// variables — appended after the base style so it wins by cascade order, and
// only for the variables the tenant actually set. A tenant that configures
// nothing emits nothing and keeps the default dark theme byte-for-byte.
//
// SECURITY: colour values are injected into a <style> context and the logo into
// an <img src>. Both are strictly validated here (hex colours only; absolute
// http(s) logo URLs only) so an attacker-controlled tenant value cannot break
// out of the CSS string or smuggle a javascript:/data: payload into the page.

// Branding is a tenant's visual customisation of the hosted end-user pages.
// The zero value renders nothing (X-Auth default theme).
type Branding struct {
	LogoURL string // absolute http(s) URL; logo shown above the card
	Accent  string // #rgb / #rrggbb; overrides --accent + derives --on-accent
	BG      string // #rgb / #rrggbb; overrides --bg + derives panel/text/muted/line
}

// configured reports whether any branding aspect is set to a usable value.
func (b Branding) configured() bool {
	return validLogoURL(b.LogoURL) || validHexColor(b.Accent) || validHexColor(b.BG)
}

var hexColorRe = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// validHexColor accepts #rgb and #rrggbb. This is the only colour syntax let
// through into the generated CSS, so the value can never contain characters
// (`}`, `<`, `;`) that would escape the rule.
func validHexColor(s string) bool { return hexColorRe.MatchString(s) }

// validLogoURL accepts an absolute http(s) URL only. Other schemes
// (javascript:, data:) are rejected so the value is safe in an <img src>.
func validLogoURL(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http"
}

// brandingCSS returns a <style> block overriding the theme variables the tenant
// configured, or "" when nothing valid is set. Safe to interpolate into <head>.
func brandingCSS(b Branding) string {
	var vars []string
	if validHexColor(b.Accent) {
		vars = append(vars, "--accent:"+b.Accent, "--on-accent:"+onColor(b.Accent))
	}
	if validHexColor(b.BG) {
		on := onColor(b.BG)
		vars = append(vars,
			"--bg:"+b.BG,
			"--text:"+on,
			"--panel:"+mixHex(b.BG, on, 0.06),
			"--muted:"+rgbaOf(on, 0.55),
			"--line:"+rgbaOf(on, 0.14),
		)
	}
	if len(vars) == 0 {
		return ""
	}
	return "<style>:root{" + strings.Join(vars, ";") + "}</style>"
}

// brandLogoHTML returns an <img> for the tenant logo, or "" when none is set.
func brandLogoHTML(b Branding) string {
	if !validLogoURL(b.LogoURL) {
		return ""
	}
	return `<img class="brand-logo" src="` + html.EscapeString(b.LogoURL) + `" alt="">`
}

// brandLogoCSS is the shared rule for the injected logo. Included in every
// hosted page's base <style> so brandLogoHTML lands consistently.
const brandLogoCSS = `.brand-logo{display:block;max-height:44px;max-width:180px;margin:0 auto 18px;object-fit:contain}`

// parseHex parses #rgb / #rrggbb into 8-bit components.
func parseHex(s string) (r, g, b uint8, ok bool) {
	if !validHexColor(s) {
		return 0, 0, 0, false
	}
	h := s[1:]
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return uint8(v >> 16), uint8(v >> 8), uint8(v), true
}

// luminance returns the perceptual relative luminance (0..1) of a hex colour.
func luminance(s string) float64 {
	r, g, b, ok := parseHex(s)
	if !ok {
		return 0
	}
	return (0.2126*float64(r) + 0.7152*float64(g) + 0.0722*float64(b)) / 255
}

// onColor picks a readable foreground (near-black or near-white) for text/icons
// placed on top of the given colour.
func onColor(bg string) string {
	if luminance(bg) > 0.55 {
		return "#0b0b0d"
	}
	return "#f5f6f8"
}

// mixHex blends a and b by t (0 = all a, 1 = all b) and returns #rrggbb. Used to
// derive a panel colour a few percent off the page background.
func mixHex(a, b string, t float64) string {
	ar, ag, ab, ok1 := parseHex(a)
	br, bg, bb, ok2 := parseHex(b)
	if !ok1 || !ok2 {
		return a
	}
	mix := func(x, y uint8) uint8 { return uint8(float64(x) + (float64(y)-float64(x))*t) }
	return fmt.Sprintf("#%02x%02x%02x", mix(ar, br), mix(ag, bg), mix(ab, bb))
}

// rgbaOf returns an rgba() string for a hex colour at alpha a. Used for muted
// text and hairlines derived from the foreground colour.
func rgbaOf(hex string, a float64) string {
	r, g, b, ok := parseHex(hex)
	if !ok {
		return hex
	}
	return fmt.Sprintf("rgba(%d,%d,%d,%.2f)", r, g, b, a)
}
