package internal

import (
	"bytes"
	"embed"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
)

// quickstart.go generates a per-tenant, ready-to-run OIDC starter kit (auth.js
// + callback.html + landing.html) for a workspace's PUBLIC client. The owner
// downloads these from the dashboard; everything tenant-specific (issuer, client
// id, tenant id, brand) is filled in from the registry, so the files run as-is
// once dropped onto a static host with the redirect URI registered.
//
// These assets ship to the browser, so they carry NO client secret — the
// download path is only ever offered for a public (PKCE) client.

//go:embed quickstart_assets/*.tmpl
var quickstartFS embed.FS

// auth.js is JavaScript (text/template — no HTML escaping); the two HTML files
// go through html/template so a brand name with markup can't break out.
var (
	quickstartJS   = texttemplate.Must(texttemplate.ParseFS(quickstartFS, "quickstart_assets/auth.js.tmpl"))
	quickstartHTML = htmltemplate.Must(htmltemplate.ParseFS(quickstartFS, "quickstart_assets/*.html.tmpl"))
)

// quickstartAsset is one downloadable starter file.
type quickstartAsset struct {
	Download    string // filename the owner saves it as
	Template    string // embedded template name
	ContentType string
	HTML        bool // render via html/template (true) or text/template (false)
}

// quickstartAssets is the ordered set offered on the dashboard. The download
// route resolves the {asset} path segment against the Download names.
var quickstartAssets = []quickstartAsset{
	{Download: "auth.js", Template: "auth.js.tmpl", ContentType: "text/javascript; charset=utf-8"},
	{Download: "callback.html", Template: "callback.html.tmpl", ContentType: "text/html; charset=utf-8", HTML: true},
	{Download: "landing.html", Template: "landing.html.tmpl", ContentType: "text/html; charset=utf-8", HTML: true},
}

func quickstartAssetByName(name string) (quickstartAsset, bool) {
	for _, a := range quickstartAssets {
		if a.Download == name {
			return a, true
		}
	}
	return quickstartAsset{}, false
}

// quickstartParams is the substitution data for the starter templates.
type quickstartParams struct {
	Issuer    string
	ClientID  string
	TenantID  string
	Company   string
	AcrValues string
}

// quickstartParamsFor builds the substitution data from a workspace's tenant
// and client. AcrValues is left empty so the starter works without step-up; the
// owner can switch on 'urn:xauth:otp:sms' in the generated auth.js.
func quickstartParamsFor(issuer string, t Tenant, c OIDCClient) quickstartParams {
	return quickstartParams{
		Issuer:    strings.TrimRight(issuer, "/"),
		ClientID:  c.ClientID,
		TenantID:  t.ID,
		Company:   t.CompanyName,
		AcrValues: "",
	}
}

// renderQuickstart fills one starter asset for a workspace.
func renderQuickstart(a quickstartAsset, p quickstartParams) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	if a.HTML {
		err = quickstartHTML.ExecuteTemplate(&buf, a.Template, p)
	} else {
		err = quickstartJS.ExecuteTemplate(&buf, a.Template, p)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
