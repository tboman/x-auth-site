package internal

// enroll_mdl.go is the self-service mDL enrollment journey: a tenant's user signs
// in with Google, then proves their mobile driving licence with their wallet and
// the verified credential is attached to their own account — no owner step.
//
// The user authenticates first, so the binding "which account gets the mDL" is
// the *server's* enrollment session, never a client-supplied id. The id-service
// verification is created server-side and polled; on success its proof token is
// verified (audience-bound to the tenant) and stored as the user's mdl anchor.
//
// Entry: GET /enroll/mdl?client_id=<tenant client> — a shareable per-tenant link.
// Both UX paths work from one verification: a same-device button and a QR for
// cross-device (scan with the phone holding the wallet); authn polls either way.

import (
	"encoding/base64"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	enrollSessionCookie = "xauth_enroll_session" // "tenantID|sessionID"
	enrollStateCookie   = "xauth_enroll_state"   // Google leg CSRF nonce
	enrollTenantCookie  = "xauth_enroll_tenant"  // target tenant across the Google leg
	enrollVrfCookie     = "xauth_enroll_vrf"     // the in-flight verification id (browser-bound)
)

// mdlEnrollClaims are the mDL data elements requested for enrollment.
var mdlEnrollClaims = []string{"family_name", "given_name", "birth_date", "document_number"}

// EnrollMDLStart begins enrollment: resolve the tenant from client_id, then run
// the Google login leg, returning to the callback.
func (h *SignupConsoleHandlers) EnrollMDLStart(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	client, err := h.Store.GetClient(clientID)
	if err != nil || client.TenantID == "" {
		h.errorPage(w, http.StatusBadRequest, "Unknown application. Use the enrollment link your provider gave you.", "/")
		return
	}
	state := randToken(32)
	h.setShortCookie(w, enrollStateCookie, state, "/enroll")
	h.setShortCookie(w, enrollTenantCookie, client.TenantID, "/enroll")
	h.startGoogle(w, r, state, h.issuerURL("/enroll/mdl/callback"))
}

// EnrollMDLCallback resolves the verified Google email to a user in the target
// tenant (creating one on first sign-in), opens a short enrollment session, and
// sends the user to the verification page.
func (h *SignupConsoleHandlers) EnrollMDLCallback(w http.ResponseWriter, r *http.Request) {
	email, ok := h.consumeGoogleEmail(w, r, enrollStateCookie, "/enroll")
	if !ok {
		return
	}
	tc, err := r.Cookie(enrollTenantCookie)
	if err != nil || tc.Value == "" {
		h.errorPage(w, http.StatusBadRequest, "Your enrollment link expired. Start again.", "/")
		return
	}
	tenantID := tc.Value
	h.clearCookie(w, enrollTenantCookie, "/enroll")

	user, err := h.Store.GetUserByEmail(tenantID, email)
	if err != nil {
		now := time.Now().UTC()
		user, err = h.Store.CreateUser(User{ID: "usr_" + uuid.NewString(), TenantID: tenantID, Email: email, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			h.Logger.Error("enroll_user_create_failed", "err", err, "tenant_id", tenantID)
			h.errorPage(w, http.StatusBadGateway, "Could not start enrollment.", "/")
			return
		}
	}
	now := time.Now().UTC()
	sess := Session{
		ID: "ses_" + uuid.NewString(), TenantID: tenantID, UserID: user.ID, RiskLevel: RiskLow,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	if _, err := h.Store.CreateSession(sess); err != nil {
		h.Logger.Error("enroll_session_create_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not start enrollment.", "/")
		return
	}
	h.setEnrollSessionCookie(w, tenantID, sess.ID, sess.ExpiresAt)
	http.Redirect(w, r, "/enroll/mdl/page", http.StatusFound)
}

// currentEnrollUser resolves the enrollment session cookie to (tenant, user).
func (h *SignupConsoleHandlers) currentEnrollUser(w http.ResponseWriter, r *http.Request) (string, User, bool) {
	c, err := r.Cookie(enrollSessionCookie)
	if err != nil || c.Value == "" {
		return "", User{}, false
	}
	tenantID, sessionID, found := strings.Cut(c.Value, "|")
	if !found || tenantID == "" || sessionID == "" {
		h.clearCookie(w, enrollSessionCookie, "/enroll")
		return "", User{}, false
	}
	sess, err := h.Store.GetSession(tenantID, sessionID)
	if err != nil || sess.InvalidatedAt != nil || time.Now().UTC().After(sess.ExpiresAt) {
		h.clearCookie(w, enrollSessionCookie, "/enroll")
		return "", User{}, false
	}
	user, err := h.Store.GetUser(tenantID, sess.UserID)
	if err != nil {
		h.clearCookie(w, enrollSessionCookie, "/enroll")
		return "", User{}, false
	}
	return tenantID, user, true
}

// EnrollMDLPage creates the verification and renders the dual-path UI.
func (h *SignupConsoleHandlers) EnrollMDLPage(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := h.currentEnrollUser(w, r)
	if !ok {
		h.errorPage(w, http.StatusForbidden, "Your enrollment session expired. Open your enrollment link again.", "/")
		return
	}
	if h.IDClient == nil || h.MDLVerifier == nil {
		h.errorPage(w, http.StatusNotImplemented, "mDL enrollment isn't configured for this deployment.", "/")
		return
	}
	vrfID, verifyURL, err := h.IDClient.Create(r.Context(), tenantID, "Enroll your mobile driving licence", mdlEnrollClaims, "link")
	if err != nil {
		h.Logger.Error("enroll_create_verification_failed", "err", err, "tenant_id", tenantID)
		h.errorPage(w, http.StatusBadGateway, "Could not start the licence check. Please try again.", "/enroll/mdl/page")
		return
	}
	h.setShortCookie(w, enrollVrfCookie, vrfID, "/enroll")
	h.page(w, http.StatusOK, "Add your mobile driving licence", h.enrollPageBody(user.Email, verifyURL))
}

// enrollPageBody is the standalone enrollment page (heading + the shared inner UI).
func (h *SignupConsoleHandlers) enrollPageBody(email, verifyURL string) string {
	return `<h1 style="margin:0 0 6px">Add your mobile driving licence</h1>
<p class="muted" style="margin:0 0 20px">Signed in as <strong>` + html.EscapeString(email) + `</strong>. Verify your mDL once and it becomes a sign-in credential on your account.</p>` +
		h.enrollInner(verifyURL)
}

// enrollInner is the dual-path verification UI (same-device button + cross-device
// QR) plus the status poller — reused standalone and embedded in the post-signup
// workspace-ready screen.
func (h *SignupConsoleHandlers) enrollInner(verifyURL string) string {
	qr := ""
	if png, err := qrcode.Encode(verifyURL, qrcode.Medium, 240); err == nil {
		qr = `<img alt="Scan with your phone" width="240" height="240" style="background:#fff;padding:10px;border-radius:10px" src="data:image/png;base64,` +
			base64.StdEncoding.EncodeToString(png) + `">`
	}
	esc := html.EscapeString(verifyURL)
	return `<div class="panel" style="display:grid;gap:22px">
  <div>
    <h3 style="margin:0 0 8px">On this device</h3>
    <p class="muted" style="margin:0 0 10px">If your wallet is on this device, verify directly.</p>
    <a class="btn" href="` + esc + `">Verify with your wallet</a>
  </div>
  <div style="border-top:1px solid var(--line);padding-top:18px">
    <h3 style="margin:0 0 8px">Use your phone</h3>
    <p class="muted" style="margin:0 0 12px">Scan this with the phone that holds your mDL wallet.</p>
    ` + qr + `
  </div>
</div>
<div id="status" class="panel" style="margin-top:16px;text-align:center">
  <span class="muted">Waiting for your wallet… keep this page open.</span>
</div>
<script>
(function(){
  var box=document.getElementById('status');
  function poll(){
    fetch('/enroll/mdl/status',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){
      if(d.status==='done'){ box.innerHTML='<strong style="color:var(--accent)">✓ mDL added to your account</strong><br><span class="muted">Trust anchor: <code>'+(d.anchor||'')+'</code></span>'; return; }
      if(d.status==='failed'||d.status==='expired'){ box.innerHTML='<strong style="color:var(--danger)">Verification '+d.status+'</strong><br><span class="muted">Please start again.</span>'; return; }
      if(d.status==='error'){ box.innerHTML='<span class="muted">Temporary problem checking status — retrying…</span>'; }
      setTimeout(poll,2500);
    }).catch(function(){ setTimeout(poll,3000); });
  }
  setTimeout(poll,2500);
})();
</script>`
}

// setEnrollSessionCookie binds the enrollment session (tenant|session) to /enroll.
func (h *SignupConsoleHandlers) setEnrollSessionCookie(w http.ResponseWriter, tenantID, sessionID string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: enrollSessionCookie, Value: tenantID + "|" + sessionID, Path: "/enroll",
		Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// mdlEnrollSection sets up enrollment for an already-authenticated session (reuses
// it, no re-login) and returns an embeddable UI block — used to start mDL
// enrollment right after tenant signup. Best-effort: returns "" when the feature
// is unconfigured or id-service can't be reached, so it never blocks signup.
func (h *SignupConsoleHandlers) mdlEnrollSection(w http.ResponseWriter, r *http.Request, tenantID, sessionID, email string, expires time.Time) string {
	if h.IDClient == nil || h.MDLVerifier == nil {
		return ""
	}
	vrfID, verifyURL, err := h.IDClient.Create(r.Context(), tenantID, "Verify your identity", mdlEnrollClaims, "link")
	if err != nil {
		h.Logger.Warn("signup_mdl_enroll_init_failed", "err", err, "tenant_id", tenantID)
		return ""
	}
	h.setEnrollSessionCookie(w, tenantID, sessionID, expires)
	h.setShortCookie(w, enrollVrfCookie, vrfID, "/enroll")
	return `<h2 style="margin-top:30px">Verify your identity <span class="muted" style="font-weight:400">(optional)</span></h2>
<p class="muted">Add your mobile driving licence now as a strong sign-in credential — or skip and do it later from your dashboard.</p>` +
		h.enrollInner(verifyURL)
}

// EnrollMDLStatus is polled by the page. It checks id-service and, on a verified
// result, validates the proof and stores the user's mdl anchor. JSON only.
func (h *SignupConsoleHandlers) EnrollMDLStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := h.currentEnrollUser(w, r)
	if !ok {
		writeEnrollJSON(w, http.StatusUnauthorized, "expired", "")
		return
	}
	vc, err := r.Cookie(enrollVrfCookie)
	if err != nil || vc.Value == "" {
		writeEnrollJSON(w, http.StatusOK, "none", "")
		return
	}
	status, proofToken, err := h.IDClient.Get(r.Context(), tenantID, vc.Value)
	if err != nil {
		h.Logger.Warn("enroll_status_fetch_failed", "err", err, "tenant_id", tenantID)
		writeEnrollJSON(w, http.StatusOK, "error", "")
		return
	}
	switch status {
	case idStatusVerified:
		proof, verr := h.MDLVerifier.Verify(r.Context(), proofToken, tenantID)
		if verr != nil {
			h.Logger.Warn("enroll_proof_invalid", "err", verr, "tenant_id", tenantID)
			writeEnrollJSON(w, http.StatusOK, "error", "")
			return
		}
		anchor, aerr := h.storeMDLAnchor(tenantID, user.ID, proof)
		if aerr != nil {
			h.Logger.Error("enroll_store_anchor_failed", "err", aerr, "tenant_id", tenantID, "user_id", user.ID)
			writeEnrollJSON(w, http.StatusOK, "error", "")
			return
		}
		h.clearCookie(w, enrollVrfCookie, "/enroll")
		h.Logger.Info("enroll_mdl_completed", "tenant_id", tenantID, "user_id", user.ID, "trust_anchor", anchor)
		writeEnrollJSON(w, http.StatusOK, "done", anchor)
	case idStatusFailed, idStatusExpired:
		h.clearCookie(w, enrollVrfCookie, "/enroll")
		writeEnrollJSON(w, http.StatusOK, status, "")
	default:
		writeEnrollJSON(w, http.StatusOK, "pending", "")
	}
}

func writeEnrollJSON(w http.ResponseWriter, code int, status, anchor string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"status":` + jsonString(status) + `,"anchor":` + jsonString(anchor) + `}`))
}

// storeMDLAnchor replaces the user's mdl anchor with the proof's trust anchor.
// Shared by self-enrollment and the owner Record-mDL action.
func (h *SignupConsoleHandlers) storeMDLAnchor(tenantID, userID string, proof MDLProof) (string, error) {
	anchor := proof.TrustAnchor
	if anchor == "" {
		anchor = proof.IssuerCN
	}
	if anchor == "" {
		anchor = "unknown issuer"
	}
	if anchors, err := h.Store.ListIdentityAnchors(tenantID); err == nil {
		for _, a := range anchors {
			if a.UserID == userID && a.Type == AnchorMDL {
				_ = h.Store.DeleteIdentityAnchor(tenantID, a.ID)
			}
		}
	}
	now := time.Now().UTC()
	_, err := h.Store.CreateIdentityAnchor(IdentityAnchor{
		ID: "ian_" + uuid.NewString(), UserID: userID, TenantID: tenantID,
		Type: AnchorMDL, Value: anchor, VerifiedAt: &now, CreatedAt: now,
	})
	return anchor, err
}

// jsonString is a tiny string-quoter for the fixed-shape status payload.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
