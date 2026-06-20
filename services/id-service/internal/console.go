package internal

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Console renders the two server-rendered UIs: the consumer "Verify with Wallet"
// page (token-gated) and the support-agent dashboard.
type Console struct {
	mgr    *Manager
	tmpl   *template.Template
	logger *slog.Logger
}

func NewConsole(mgr *Manager, logger *slog.Logger) (*Console, error) {
	t, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Console{mgr: mgr, tmpl: t, logger: logger}, nil
}

type verifyData struct {
	State       string // ready | done | failed | expired | notfound
	ID          string
	Purpose     string
	DocType     string
	Assurance   string
	RequestJSON template.JS
	ResponseURL string
}

// VerifyPage renders the consumer page for a one-time token.
func (c *Console) VerifyPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	v, err := c.mgr.GetByToken(r.Context(), token)
	if err != nil {
		c.render(w, "verify.html", verifyData{State: "notfound"})
		return
	}
	now := time.Now().UTC()
	data := verifyData{ID: v.ID, Purpose: v.Purpose, DocType: v.DocType}
	switch {
	case v.Status == StatusVerified:
		data.State = "done"
		if v.Result != nil {
			data.Assurance = v.Result.Assurance
		}
	case v.Status == StatusFailed:
		data.State = "failed"
	case now.After(v.ExpiresAt):
		data.State = "expired"
	case v.Status != StatusPending:
		data.State = "failed"
	default:
		data.State = "ready"
		b, _ := json.Marshal(buildOID4VPRequest(v))
		data.RequestJSON = template.JS(b) //nolint:gosec // server-built JSON, not user input
		data.ResponseURL = "/v1/verifications/" + v.ID + "/response"
	}
	c.render(w, "verify.html", data)
}

// Dashboard renders the agent console. The page calls the same-origin tenant API
// (X-Tenant-Id set client-side in phase 1; X-Auth OIDC session gating is the
// production hook — see README).
func (c *Console) Dashboard(w http.ResponseWriter, _ *http.Request) {
	c.render(w, "dashboard.html", map[string]any{
		"DefaultNamespace": DefaultNamespace,
		"DocType":          DefaultDocType,
	})
}

// Root is a minimal landing that points at the dashboard + docs.
func (c *Console) Root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	c.render(w, "landing.html", nil)
}

func (c *Console) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.tmpl.ExecuteTemplate(w, name, data); err != nil {
		c.logger.Error("template_render_failed", "template", name, "err", err)
	}
}
