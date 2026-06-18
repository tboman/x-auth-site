package internal

// webauthn_stepup.go drives the FIDO2/passkey step-up on the authentication
// service side: it hosts the browser ceremony page and proxies the
// register-on-first-use begin/finish calls to authenticator-service. The crypto
// (options generation, attestation/assertion verification, credential storage)
// all lives in authenticator-service; this side only orchestrates the browser.

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/xentranet/x-auth/pkg/httpx"
)

// startWebAuthnStepUp begins a passkey step-up. With an enrolled passkey it
// creates an assertion challenge and renders the assertion page; with none it
// renders the registration page (register-on-first-use), which runs the
// registration ceremony and then continues into the assertion.
func (h *OIDCHandlers) startWebAuthnStepUp(w http.ResponseWriter, r *http.Request, spec stepUpSpec, p pendingAuthorize) {
	ctx := r.Context()
	auths, err := h.Authenticator.ListAuthenticators(ctx, p.TenantID, p.UserID)
	if err != nil {
		h.Logger.Error("stepup_list_authenticators_failed", "err", err, "user_id", p.UserID, "method", spec.Method)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not reach authenticator service")
		return
	}
	hasPasskey := false
	for _, a := range auths {
		if a.Method == stepUpMethodFIDO2 && a.Status != "disabled" {
			hasPasskey = true
			break
		}
	}

	p.Method = spec.Method
	p.CreatedAt = time.Now().UTC()
	flowID := uuid.NewString()

	if !hasPasskey {
		// Register-on-first-use: park the flow and serve the registration page.
		h.storeFlow(flowID, p)
		h.StepUps.Start(StepUpAttempt{FlowID: flowID, TenantID: p.TenantID, UserID: p.UserID, Method: spec.Method, StartedAt: p.CreatedAt})
		h.Logger.Info("stepup_webauthn_register_started", "flow_id", flowID, "user_id", p.UserID, "tenant_id", p.TenantID)
		h.renderWebAuthnForm(w, http.StatusOK, webAuthnFormData{FlowID: flowID, Register: true})
		return
	}

	chal, err := h.Authenticator.CreateChallenge(ctx, p.TenantID, p.UserID, []string{stepUpMethodFIDO2})
	if err != nil {
		h.Logger.Error("stepup_challenge_create_failed", "err", err, "user_id", p.UserID, "method", spec.Method)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not create passkey challenge")
		return
	}
	p.ChallengeID = chal.ChallengeID
	p.Prompt = chal.Prompt
	p.WebAuthnOptions = string(chal.Options)
	h.storeFlow(flowID, p)
	h.StepUps.Start(StepUpAttempt{FlowID: flowID, TenantID: p.TenantID, UserID: p.UserID, Method: spec.Method, StartedAt: p.CreatedAt})
	h.Logger.Info("stepup_flow_started", "flow_id", flowID, "challenge_id", chal.ChallengeID,
		"user_id", p.UserID, "tenant_id", p.TenantID, "method", spec.Method)
	h.renderWebAuthnForm(w, http.StatusOK, webAuthnFormData{FlowID: flowID, AssertionOptions: string(chal.Options)})
}

// AuthorizeWebAuthnRegisterBegin proxies POST /authorize/webauthn/register/begin
// — the hosted page asks for credential-creation options for the parked flow's
// user.
func (h *OIDCHandlers) AuthorizeWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Flow string `json:"flow"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	flow, ok := h.peekFlow(body.Flow)
	if !ok || flow.Method != stepUpMethodFIDO2 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "flow is invalid or expired — restart the login")
		return
	}
	name, displayName := h.webAuthnUserName(flow.TenantID, flow.UserID)
	reg, err := h.Authenticator.WebAuthnRegisterBegin(r.Context(), flow.TenantID, flow.UserID, name, displayName)
	if err != nil {
		h.Logger.Error("stepup_webauthn_register_begin_failed", "err", err, "flow_id", body.Flow)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not begin registration")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"registration_id": reg.RegistrationID, "options": reg.Options})
}

// AuthorizeWebAuthnRegisterFinish proxies POST /authorize/webauthn/register/finish
// — it validates+persists the new passkey, then creates the assertion challenge
// and returns its options so the page continues straight into the assertion.
func (h *OIDCHandlers) AuthorizeWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Flow           string          `json:"flow"`
		RegistrationID string          `json:"registration_id"`
		Attestation    json.RawMessage `json:"attestation"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	flow, ok := h.peekFlow(body.Flow)
	if !ok || flow.Method != stepUpMethodFIDO2 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_grant", "flow is invalid or expired — restart the login")
		return
	}
	if _, err := h.Authenticator.WebAuthnRegisterFinish(r.Context(), flow.TenantID, flow.UserID, body.RegistrationID, body.Attestation); err != nil {
		// A 4xx from authenticator-service is a bad/expired attestation (client
		// error); anything else is the service being unavailable.
		var de *DownstreamError
		if errors.As(err, &de) && de.Status >= 400 && de.Status < 500 {
			h.Logger.Info("stepup_webauthn_register_rejected", "flow_id", body.Flow, "status", de.Status)
			httpx.WriteError(w, http.StatusBadRequest, "registration_failed", "passkey registration failed — try again")
			return
		}
		h.Logger.Error("stepup_webauthn_register_finish_failed", "err", err, "flow_id", body.Flow)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not complete registration")
		return
	}

	chal, err := h.Authenticator.CreateChallenge(r.Context(), flow.TenantID, flow.UserID, []string{stepUpMethodFIDO2})
	if err != nil {
		h.Logger.Error("stepup_challenge_create_failed", "err", err, "flow_id", body.Flow)
		httpx.WriteError(w, http.StatusBadGateway, "authenticator_unavailable", "could not create passkey challenge")
		return
	}
	flow.ChallengeID = chal.ChallengeID
	flow.Prompt = chal.Prompt
	flow.WebAuthnOptions = string(chal.Options)
	h.storeFlow(body.Flow, flow)
	h.Logger.Info("stepup_webauthn_registered", "flow_id", body.Flow, "challenge_id", chal.ChallengeID, "tenant_id", flow.TenantID)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"options": chal.Options})
}

// webAuthnUserName resolves a human label for a registration ceremony. Email is
// preferred; then a display name; then the phone anchor; finally the user id.
func (h *OIDCHandlers) webAuthnUserName(tenantID, userID string) (name, displayName string) {
	if u, err := h.Store.GetUser(tenantID, userID); err == nil {
		switch {
		case u.Email != "":
			name = u.Email
		case u.Name != "":
			name = u.Name
		}
		displayName = u.Name
	}
	if name == "" {
		if phone, ok := h.userPhone(tenantID, userID); ok {
			name = phone
		} else {
			name = userID
		}
	}
	if displayName == "" {
		displayName = name
	}
	return name, displayName
}

// renderStepUpRetry re-renders the right verification page after a failed or
// throttled attempt: the passkey page for fido2, the OTP page otherwise.
func (h *OIDCHandlers) renderStepUpRetry(w http.ResponseWriter, status int, flow pendingAuthorize, flowID, errMsg string) {
	if flow.Method == stepUpMethodFIDO2 {
		h.renderWebAuthnForm(w, status, webAuthnFormData{FlowID: flowID, AssertionOptions: flow.WebAuthnOptions, Error: errMsg})
		return
	}
	h.renderOTPForm(w, status, otpFormData{FlowID: flowID, Prompt: flow.Prompt, Method: flow.Method, Error: errMsg})
}

// webAuthnFormData feeds the passkey page. Register selects the
// register-then-assert flow; AssertionOptions (raw JSON) is present for the
// assert-only flow and on retry.
type webAuthnFormData struct {
	FlowID           string
	Error            string
	Register         bool
	AssertionOptions string
}

type webAuthnTmplData struct {
	FlowID     string
	Error      string
	Register   bool        // drives the {{if}} HTML branch
	RegisterJS template.JS // the JS boolean literal
	Options    template.JS // assertion options JSON, or "null"
}

func (h *OIDCHandlers) renderWebAuthnForm(w http.ResponseWriter, status int, data webAuthnFormData) {
	opts := template.JS("null")
	if data.AssertionOptions != "" {
		opts = template.JS(data.AssertionOptions)
	}
	regJS := template.JS("false")
	if data.Register {
		regJS = template.JS("true")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := webAuthnTmpl.Execute(w, webAuthnTmplData{
		FlowID: data.FlowID, Error: data.Error, Register: data.Register, RegisterJS: regJS, Options: opts,
	}); err != nil {
		h.Logger.Error("webauthn_form_render_failed", "err", err)
	}
}

var webAuthnTmpl = template.Must(template.New("webauthn").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify your identity — X-Auth</title>
<style>
  body { background:#09090b; color:#dddde4; font-family:system-ui,sans-serif;
         display:grid; place-items:center; min-height:100vh; margin:0 }
  .card { background:rgba(18,18,22,.85); border:1px solid rgba(255,255,255,.07);
          border-radius:12px; padding:2.5rem; max-width:24rem; text-align:center }
  h1 { font-size:1.1rem; margin:0 0 .75rem }
  p  { color:#7c7c8a; font-size:.9rem; margin:0 0 1.25rem }
  .err { color:#f04040; font-size:.85rem; margin:0 0 1rem }
  button { width:100%; margin-top:.5rem; background:#00e096; color:#000; font-weight:700;
           border:0; border-radius:6px; padding:.8rem; font-size:1rem; cursor:pointer }
  button:disabled { opacity:.6; cursor:default }
</style>
</head>
<body>
<div class="card">
  {{if .Register}}<h1>Create a passkey</h1><p>Set up a passkey on this device to continue securely.</p>
  {{else}}<h1>Confirm with your passkey</h1><p>Use your passkey (fingerprint, face, or security key) to continue.</p>{{end}}
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <p id="status"></p>
  <button id="go" type="button">{{if .Register}}Create passkey{{else}}Use passkey{{end}}</button>
  <form id="verifyForm" method="POST" action="/authorize/verify" style="display:none">
    <input type="hidden" name="flow" value="{{.FlowID}}">
    <input type="hidden" name="assertion" id="assertion">
    <input type="hidden" name="device_fp" data-device-fp>
  </form>
</div>
<script>
(function(){
  var FLOW = "{{.FlowID}}";
  var REGISTER = {{.RegisterJS}};
  var ASSERT_OPTS = {{.Options}};
  var statusEl = document.getElementById('status');
  var btn = document.getElementById('go');

  function b64uToBuf(s){
    s = String(s).replace(/-/g,'+').replace(/_/g,'/');
    while(s.length % 4) s += '=';
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++){ buf[i]=bin.charCodeAt(i); }
    return buf.buffer;
  }
  function bufToB64u(buf){
    var b = new Uint8Array(buf), s='';
    for(var i=0;i<b.length;i++){ s += String.fromCharCode(b[i]); }
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
  function setStatus(m){ if(statusEl){ statusEl.textContent = m; } }
  function fail(m){ setStatus(m); if(btn){ btn.disabled=false; btn.textContent='Try again'; } }

  function decodeRequest(o){
    var p = o.publicKey;
    p.challenge = b64uToBuf(p.challenge);
    if(p.allowCredentials){ p.allowCredentials.forEach(function(c){ c.id = b64uToBuf(c.id); }); }
    return o;
  }
  function decodeCreation(o){
    var p = o.publicKey;
    p.challenge = b64uToBuf(p.challenge);
    p.user.id = b64uToBuf(p.user.id);
    if(p.excludeCredentials){ p.excludeCredentials.forEach(function(c){ c.id = b64uToBuf(c.id); }); }
    return o;
  }
  function encodeAssertion(c){
    var r = c.response;
    return { id:c.id, type:c.type, rawId:bufToB64u(c.rawId), response:{
      clientDataJSON:bufToB64u(r.clientDataJSON), authenticatorData:bufToB64u(r.authenticatorData),
      signature:bufToB64u(r.signature), userHandle:r.userHandle?bufToB64u(r.userHandle):null } };
  }
  function encodeAttestation(c){
    var r = c.response;
    return { id:c.id, type:c.type, rawId:bufToB64u(c.rawId), response:{
      clientDataJSON:bufToB64u(r.clientDataJSON), attestationObject:bufToB64u(r.attestationObject) } };
  }
  function postJSON(url, body){
    return fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
      .then(function(resp){ if(!resp.ok){ return resp.text().then(function(t){ throw new Error(t||resp.status); }); } return resp.json(); });
  }
  function clone(o){ return JSON.parse(JSON.stringify(o)); }

  function assert(opts){
    setStatus('Waiting for your passkey...');
    return navigator.credentials.get(decodeRequest(clone(opts))).then(function(cred){
      document.getElementById('assertion').value = JSON.stringify(encodeAssertion(cred));
      document.getElementById('verifyForm').submit();
    });
  }
  function register(){
    setStatus('Create a passkey to continue...');
    var regID;
    return postJSON('/authorize/webauthn/register/begin', {flow:FLOW}).then(function(begin){
      regID = begin.registration_id;
      return navigator.credentials.create(decodeCreation(clone(begin.options)));
    }).then(function(cred){
      setStatus('Saving your passkey...');
      return postJSON('/authorize/webauthn/register/finish', {flow:FLOW, registration_id:regID, attestation:encodeAttestation(cred)});
    }).then(function(finish){ return assert(finish.options); });
  }
  function start(){
    if(!window.PublicKeyCredential){ fail('This browser does not support passkeys.'); return; }
    if(btn){ btn.disabled=true; }
    var p = REGISTER ? register() : assert(ASSERT_OPTS);
    p.catch(function(e){ fail('Could not complete: ' + (e && e.message ? e.message : e)); });
  }
  if(btn){ btn.addEventListener('click', start); }
})();
</script>
` + deviceFPScript + `
</body>
</html>
`))
