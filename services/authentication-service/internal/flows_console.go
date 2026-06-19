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

// flowsSection renders the Flows tab. editID (from ?edit=) loads that flow into
// the editor for in-place editing; empty starts a blank custom flow.
func (h *SignupConsoleHandlers) flowsSection(tenantID, editID string) string {
	flows, _ := h.Store.ListFlows(tenantID)

	var rows strings.Builder
	if len(flows) == 0 {
		rows.WriteString(`<tr><td colspan="4" class="muted">No flows yet. Apply the risk-adaptive template, or author one below.</td></tr>`)
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
			`<a class="btn secondary" href="/admin?tab=flows&edit=` + html.EscapeString(f.ID) + `#editor">Edit</a>` +
			`<form method="post" action="/admin/owner/flows/enable"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><input type="hidden" name="enabled" value="` + toggleVal + `"><button class="secondary" type="submit">` + toggleLabel + `</button></form>` +
			`<form method="post" action="/admin/owner/flows/validate"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><button class="secondary" type="submit">Validate</button></form>` +
			`<form method="post" action="/admin/owner/flows/delete" onsubmit="return confirm('Delete this flow?')"><input type="hidden" name="id" value="` + html.EscapeString(f.ID) + `"><button class="danger" type="submit">Delete</button></form>` +
			`</div></td></tr>`)
	}

	// Resolve the editor's initial state: editing an existing flow, or a blank new one.
	var edit FlowDefinition
	if editID != "" {
		if f, err := h.Store.GetFlow(tenantID, editID); err == nil {
			edit = f
		}
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
<p class="muted" style="margin:0 0 10px">Add the ready-made risk-adaptive step-up flow (you can edit or disable it any time):</p>
<div class="actions"><button type="submit">Apply risk-adaptive template</button></div>
</form></div>` +
		h.flowEditorPanel(edit, "", "") +
		`<p class="muted">Note: risk-adaptive decisions need the X-Auth flow engine switched on for your workspace. If a flow looks
enabled but behavior is unchanged, contact X-Auth to enable it.</p>`
}

// blankFlowStagesJSON is the starter document shown when authoring a new flow.
const blankFlowStagesJSON = `[
  {"type": "risk-evaluation"},
  {"type": "deny", "config": {"reason": "high-risk location"},
   "policies": [{"name": "deny-impossible-travel", "expression": "risk.impossible_travel"}]},
  {"type": "authenticator-validate",
   "policies": [{"name": "skip-when-low-risk", "expression": "risk.tier == \"low\"", "negate": true}]},
  {"type": "user-login"}
]`

// flowEditorPanel renders the create/edit form. def is the flow being edited
// (zero value = new). stagesJSON, when non-empty, overrides the textarea (used to
// preserve a rejected submission); errMsg shows a validation banner.
func (h *SignupConsoleHandlers) flowEditorPanel(def FlowDefinition, stagesJSON, errMsg string) string {
	if stagesJSON == "" {
		if len(def.Stages) > 0 {
			b, _ := json.MarshalIndent(def.Stages, "", "  ")
			stagesJSON = string(b)
		} else {
			stagesJSON = blankFlowStagesJSON
		}
	}
	slug := def.Slug
	if slug == "" {
		slug = "custom-stepup"
	}
	enabledAttr := ""
	if def.Enabled {
		enabledAttr = " checked"
	}
	heading := "Author a custom flow"
	if def.ID != "" {
		heading = "Edit flow"
	}
	banner := ""
	if errMsg != "" {
		banner = `<p style="color:var(--danger);margin:0 0 12px"><strong>Validation failed:</strong> ` + html.EscapeString(errMsg) + `</p>`
	}

	return `<h3 id="editor" style="margin-top:28px">` + heading + `</h3>
<p class="muted">Compose the <code>authorization-stepup</code> journey as an ordered list of stages. Each stage may carry
policies (boolean <a href="https://expr-lang.org" target="_blank" rel="noopener">expr-lang</a> expressions); a stage runs
only when its policies pass (<code>negate</code> flips that). The flow must end in a <code>user-login</code> or
<code>deny</code> stage. Saving validates every expression first — an invalid flow can't lock your users out.</p>
<div class="panel">` + banner + `<form method="post" action="/admin/owner/flows/save">
<input type="hidden" name="id" value="` + html.EscapeString(def.ID) + `">
<label>Slug</label>
<input type="text" name="slug" value="` + html.EscapeString(slug) + `" required>
<label>Title</label>
<input type="text" name="title" value="` + html.EscapeString(def.Title) + `" placeholder="Custom step-up">
<label>Stages (JSON)</label>
<textarea name="stages" rows="16" spellcheck="false" style="width:100%;font-family:ui-monospace,monospace;font-size:13px;background:#0d0d12;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:10px">` + html.EscapeString(stagesJSON) + `</textarea>
<label style="display:flex;align-items:center;gap:8px;margin-top:10px"><input type="checkbox" name="enabled" value="on"` + enabledAttr + `> Enable this flow (your users get it immediately)</label>
<div class="actions" style="margin-top:12px"><button type="submit">Save flow</button></div>
</form></div>
<details style="margin-top:8px"><summary class="muted" style="cursor:pointer">Stage types &amp; policy reference</summary>
<div class="panel" style="margin-top:8px"><p class="muted" style="margin:0 0 8px"><strong>Stage types:</strong>
<code>risk-evaluation</code> (fills <code>risk.*</code>), <code>authenticator-validate</code> (step-up / pass-through),
<code>user-login</code> (issue the code — terminal), <code>deny</code> (refuse — terminal; <code>config.reason</code>).</p>
<p class="muted" style="margin:0 0 8px"><strong>Policy env:</strong> <code>risk.{tier,score,impossible_travel,flags,device,behavior,network,user}</code>,
<code>request.{client_id,ip,device_fp,user_agent}</code>, <code>protection.{requested_rank,achieved_rank}</code>, <code>user.id</code>.</p>
<p class="muted" style="margin:0"><strong>Examples:</strong> <code>risk.tier == "low"</code> · <code>risk.score &gt;= 0.7 &amp;&amp; request.client_id == "checkout"</code> · <code>"tor_exit" in risk.flags</code></p>
</div></details>`
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

// SaveFlow handles POST /admin/owner/flows/save — create or edit a custom flow
// from the JSON editor. The submission is validated (JSON + every policy
// expression + terminal stage) before it touches storage; on failure the editor
// is re-rendered with the error and the submitted text preserved.
func (h *SignupConsoleHandlers) SaveFlow(w http.ResponseWriter, r *http.Request) {
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
	slug := strings.TrimSpace(r.PostForm.Get("slug"))
	title := strings.TrimSpace(r.PostForm.Get("title"))
	enabled := r.PostForm.Get("enabled") == "on"
	stagesJSON := r.PostForm.Get("stages")

	renderErr := func(msg string) {
		def := FlowDefinition{ID: id, Slug: slug, Title: title, Enabled: enabled}
		h.page(w, http.StatusBadRequest, "Fix your flow",
			`<h1 style="margin:0 0 8px">Flows</h1>`+h.flowEditorPanel(def, stagesJSON, msg)+
				`<div class="actions" style="margin-top:12px"><a class="btn secondary" href="/admin?tab=flows">Back to flows</a></div>`)
	}

	if slug == "" {
		renderErr("a slug is required")
		return
	}
	var stages []StageConfig
	if err := json.Unmarshal([]byte(stagesJSON), &stages); err != nil {
		renderErr("stages JSON is invalid: " + err.Error())
		return
	}
	// Edit: the supplied id must already belong to this tenant. GetFlow is
	// tenant-scoped, so a foreign id reads as not-found — this blocks overwriting
	// another workspace's flow by guessing its id.
	if id != "" {
		if _, err := h.Store.GetFlow(owner.Tenant.ID, id); err != nil {
			h.errorPage(w, http.StatusNotFound, "That flow isn't in your workspace.", "/admin?tab=flows")
			return
		}
	} else {
		id = "flo_" + uuid.NewString()
	}
	def := FlowDefinition{
		ID: id, TenantID: owner.Tenant.ID, Designation: FlowAuthorizeStepUp,
		Slug: slug, Title: title, Enabled: enabled, Stages: stages,
	}
	if err := ValidateFlowDefinition(def); err != nil {
		renderErr(err.Error())
		return
	}
	if err := h.Store.UpsertFlow(def); err != nil {
		h.Logger.Error("owner_flow_save_failed", "err", err, "tenant_id", owner.Tenant.ID)
		h.errorPage(w, http.StatusBadGateway, "Could not save the flow.", "/admin?tab=flows")
		return
	}
	h.Logger.Info("owner_flow_saved", "tenant_id", owner.Tenant.ID, "flow_id", id, "slug", slug, "enabled", enabled)
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
