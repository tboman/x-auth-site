package internal

// flows_console.go is the owner-dashboard "Flows" tab: it lets a workspace owner
// turn on the risk-adaptive authorization journey, enable/disable a flow, run the
// lockout-prevention validation, and remove a flow — without touching SQL. The
// freeform stage editor is a later increment; today the owner applies the
// code-defined risk-adaptive template and toggles it.

import (
	"encoding/json"
	"html"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// flowsSection renders the Flows tab for a tenant.
func (h *SignupConsoleHandlers) flowsSection(tenantID string) string {
	flows, _ := h.Store.ListFlows(tenantID)

	var rows strings.Builder
	if len(flows) == 0 {
		rows.WriteString(`<tr><td colspan="4" class="muted">No flows yet. Apply the risk-adaptive template below to get started.</td></tr>`)
	}
	for _, f := range flows {
		status := `<span class="muted">disabled</span>`
		toggleLabel, toggleVal := "Enable", "true"
		if f.Enabled {
			status = `<span style="color:var(--accent)">enabled</span>`
			toggleLabel, toggleVal = "Disable", "false"
		}
		pretty, _ := json.MarshalIndent(f.Stages, "", "  ")
		rows.WriteString(`<tr><td><code>` + html.EscapeString(f.Slug) + `</code><br><span class="muted">` +
			html.EscapeString(f.Designation) + `</span></td>` +
			`<td>` + status + `</td>` +
			`<td>` + itoa(len(f.Stages)) + ` stage(s)` +
			`<details style="margin-top:6px"><summary class="muted" style="cursor:pointer">definition</summary>` +
			`<pre style="margin:6px 0 0;max-height:240px;overflow:auto"><code>` + html.EscapeString(string(pretty)) + `</code></pre></details></td>` +
			`<td><div class="actions" style="gap:6px">` +
			`<form method="post" action="/admin/owner/flows/enable"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><input type="hidden" name="enabled" value="` + toggleVal + `"><button class="secondary" type="submit">` + toggleLabel + `</button></form>` +
			`<form method="post" action="/admin/owner/flows/validate"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><button class="secondary" type="submit">Validate</button></form>` +
			`<form method="post" action="/admin/owner/flows/delete" onsubmit="return confirm('Delete this flow?')"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><button class="danger" type="submit">Delete</button></form>` +
			`</div></td></tr>`)
	}

	return `<h2 style="margin-top:28px">Flows</h2>
<p class="muted">A flow is the journey <code>/authorize</code> runs. The <strong>risk-adaptive step-up</strong> flow
uses a live risk score to <em>skip</em> a step-up when the session is low-risk, <em>challenge</em> when it isn't, and
<em>deny</em> on an impossible-travel signal — instead of always challenging. The enabled flow for a designation is the
one your users get; with none enabled, X-Auth runs the built-in default (today's behavior).</p>
<div class="panel"><table>
<thead><tr><th>Flow</th><th>Status</th><th>Stages</th><th></th></tr></thead>
<tbody>` + rows.String() + `</tbody></table>
<form method="post" action="/admin/owner/flows/apply" style="margin-top:16px">
<p class="muted" style="margin:0 0 10px">Add the ready-made risk-adaptive step-up flow (you can disable it any time):</p>
<div class="actions"><button type="submit">Apply risk-adaptive template</button></div>
</form></div>
<p class="muted">Note: risk-adaptive decisions need the X-Auth flow engine switched on for your workspace. If a flow looks
enabled but behavior is unchanged, contact X-Auth to enable it.</p>`
}

// ApplyFlowTemplate handles POST /admin/owner/flows/apply — installs the
// risk-adaptive step-up template (enabled) for the owner's tenant.
func (h *SignupConsoleHandlers) ApplyFlowTemplate(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	def := RiskAdaptiveFlowDefinition("flo_"+uuid.NewString(), owner.Tenant.ID, true)
	if err := ValidateFlowDefinition(def); err != nil {
		// Should never happen for the built-in template; guard anyway.
		h.errorPage(w, http.StatusInternalServerError, "Template failed validation: "+err.Error(), "/admin?tab=flows")
		return
	}
	if err := h.Store.UpsertFlow(def); err != nil {
		h.Logger.Error("owner_flow_apply_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not apply the flow.", "/admin?tab=flows")
		return
	}
	h.Logger.Info("owner_flow_applied", "tenant_id", owner.Tenant.ID, "flow_id", def.ID, "slug", def.Slug)
	http.Redirect(w, r, "/admin?tab=flows", http.StatusFound)
}

// SetFlowEnabled handles POST /admin/owner/flows/enable — enable/disable a flow.
func (h *SignupConsoleHandlers) SetFlowEnabled(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=flows")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	enable := r.PostForm.Get("enabled") == "true"
	def, err := h.Store.GetFlow(owner.Tenant.ID, id)
	if err != nil {
		h.errorPage(w, http.StatusNotFound, "That flow isn't in your workspace.", "/admin?tab=flows")
		return
	}
	if enable {
		if verr := ValidateFlowDefinition(def); verr != nil {
			h.errorPage(w, http.StatusBadRequest, "Can't enable an invalid flow: "+verr.Error(), "/admin?tab=flows")
			return
		}
	}
	def.Enabled = enable
	if err := h.Store.UpsertFlow(def); err != nil {
		h.Logger.Error("owner_flow_toggle_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not update the flow.", "/admin?tab=flows")
		return
	}
	h.Logger.Info("owner_flow_toggled", "tenant_id", owner.Tenant.ID, "flow_id", id, "enabled", enable)
	http.Redirect(w, r, "/admin?tab=flows", http.StatusFound)
}

// ValidateFlow handles POST /admin/owner/flows/validate — compiles every bound
// expression and reports the result (the lockout-prevention check).
func (h *SignupConsoleHandlers) ValidateFlow(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=flows")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	def, err := h.Store.GetFlow(owner.Tenant.ID, id)
	if err != nil {
		h.errorPage(w, http.StatusNotFound, "That flow isn't in your workspace.", "/admin?tab=flows")
		return
	}
	if verr := ValidateFlowDefinition(def); verr != nil {
		h.errorPage(w, http.StatusBadRequest, "Validation failed: "+verr.Error(), "/admin?tab=flows")
		return
	}
	h.page(w, http.StatusOK, "Flow valid",
		`<h1>Flow is valid</h1><p class="muted"><code>`+html.EscapeString(def.Slug)+
			`</code> — all `+itoa(len(def.Stages))+` stage(s) and every bound policy expression compile.</p>`+
			`<div class="actions"><a class="btn" href="/admin?tab=flows">Back to flows</a></div>`)
}

// DeleteFlow handles POST /admin/owner/flows/delete.
func (h *SignupConsoleHandlers) DeleteFlow(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.currentOwner(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Sign in to your workspace first.", "/admin")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.errorPage(w, http.StatusBadRequest, "Could not parse the form.", "/admin?tab=flows")
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	if err := h.Store.DeleteFlow(owner.Tenant.ID, id); err != nil && err != ErrNotFound {
		h.Logger.Error("owner_flow_delete_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not delete the flow.", "/admin?tab=flows")
		return
	}
	h.Logger.Info("owner_flow_deleted", "tenant_id", owner.Tenant.ID, "flow_id", id)
	http.Redirect(w, r, "/admin?tab=flows", http.StatusFound)
}
