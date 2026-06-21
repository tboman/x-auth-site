package internal

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/jwtx"
	"github.com/xentranet/x-auth/pkg/ratex"
	"github.com/xentranet/x-auth/pkg/smsx"
	"github.com/xentranet/x-auth/pkg/tenantx"
)

// Deps bundles every collaborator authentication-service needs. Passing this to
// the router keeps cmd/main.go's constructor small and the test wiring obvious.
type Deps struct {
	Store         Storage
	Logger        *slog.Logger
	Authenticator AuthenticatorClient
	Issuer        string

	// Signer holds the RS256 key that signs access + ID tokens and backs the
	// JWKS endpoints. Required. JWTIssuer is the `iss` claim minted into
	// tokens; empty means "same as Issuer" (the normal case — tokens should
	// match the discovery document).
	Signer    *jwtx.Signer
	JWTIssuer string

	// SocialProviders enables the real OAuth2 handshake per provider (see
	// SocialHandlers). Nil/empty means every provider runs the phase-1 stub.
	SocialProviders map[string]SocialProviderConfig

	// CORSOrigins lists web origins allowed to call the public OIDC surface
	// (/token, /userinfo, /revoke, discovery, JWKS) from a browser. Empty
	// means no CORS headers are emitted (server-to-server callers only).
	CORSOrigins []string

	// AdminEmails is the Google-account allowlist for the hosted admin console
	// (/admin). Empty means the console denies all sign-ins (deny by default).
	AdminEmails []string

	// RootEmails are break-glass root accounts: always allowed into the console
	// and re-granted every staff role + reactivated on every boot (ROOT_EMAILS).
	// Empty means no root account.
	RootEmails []string

	// Events is the recent-activity feed shown in the operator Monitoring domain
	// (an in-process log ring buffer wired in cmd/main). Optional.
	Events *EventBuffer

	// Health probes the platform services for the Monitoring domain. Built in
	// cmd/main from the service URLs. Optional (nil → the panel shows no
	// services); tests omit it to stay hermetic.
	Health *HealthChecker

	// DevAutologin re-enables the legacy /authorize behaviour (trust a user_id
	// parameter / auto-create a dev user) for local development and tests.
	// OFF in production, where /authorize requires a real authz-session cookie.
	DevAutologin bool

	// StepUpFreshness: a protection-level /authorize request passes through
	// without re-challenging if the user stepped up at >= that level within this
	// window (AUTHORIZE_STEPUP_FRESHNESS). 0 → defaultStepUpFreshness (5m).
	StepUpFreshness time.Duration

	// FlowEngine routes /authorize through the configurable flow executor instead
	// of the legacy hardcoded branch (FLOW_ENGINE). OFF by default; the built-in
	// default flow reproduces the legacy behavior exactly.
	FlowEngine bool

	// Risk is an optional override for the risk-service client used by the
	// risk-evaluation stage. When nil, Router builds an HTTP client from
	// RISK_EVENTS_URL (same base as the CAEP transmitter); tests inject a mock.
	Risk RiskEvaluator

	// MDLVerifier is an optional override for the id-service mDL proof verifier.
	// When nil, Router builds an HTTP verifier from ID_ISSUER; tests inject a mock.
	MDLVerifier MDLProofVerifier

	// IDClient is an optional override for the id-service verification client used
	// by self-enrollment. When nil, Router builds an HTTP client from ID_ISSUER.
	IDClient IDVerificationClient
}

// Router builds the complete http.Handler for authentication-service.
//
// Routing tiers:
//
//   - /healthz — unauthenticated, always served
//   - /.well-known/*, /authorize, /token, /revoke, /userinfo, /v1/auth/jwks —
//     public OIDC surface, no tenant header (tenant is carried by the
//     authorization code or the bearer token's claims)
//   - /v1/social/{provider}/authorize|/callback — public social-login stub
//   - /v1/users/*, /v1/sessions/* — tenant-scoped, behind tenantx.Middleware
//   - /internal/v1/sessions/* — service-to-service alias of the session
//     endpoints (same handlers), additionally wrapped in httpx.InternalAuth
//     (ARCHITECTURE.md §10.3). transaction-service calls GET
//     /internal/v1/sessions/{id} and POST /internal/v1/sessions/{id}/upgrade
//     here. Verified mTLS peers or the X-Internal-Auth shared secret are
//     accepted; with neither configured the tree is open (local dev). Only the
//     session subtree is aliased — the OIDC/user surface stays public-only.
//
// The whole tree is wrapped in Recover + Logging so every request logs and
// handler panics turn into 500 instead of crashing the process.
func Router(d Deps) http.Handler {
	jwtIssuer := d.JWTIssuer
	if jwtIssuer == "" {
		jwtIssuer = d.Issuer
	}
	// Build the bearer verifier from the signer's own published key set — the
	// same document /v1/auth/jwks serves — so /userinfo validates tokens the
	// exact way an external consumer would. A Signer's JWKS always contains
	// one usable RSA key, so a construction error is a programming bug.
	verifier, err := jwtx.NewVerifierFromJWKS(jwtIssuer, d.Signer.JWKS())
	if err != nil {
		panic("authentication-service: verifier from signer JWKS: " + err.Error())
	}
	// Shared live-step-up registry: the OIDC step-up interlude records attempts
	// here and the consoles read them for the session-management views.
	stepUps := NewStepUpTracker(otpFlowTTL)
	// Per-session protection-level assurance ledger (protection.go). Lives as
	// long as a session so a satisfied level passes through for the session's life.
	protection := NewProtectionLedger(time.Duration(SessionTTLSeconds) * time.Second)

	// CAEP transmitter + device analyzer (caep.go / device_analyzer.go). The
	// transmitter posts signed SETs to risk-service's receiver at RISK_EVENTS_URL
	// (log-only when unset); the analyzer compares each fingerprint to history
	// and emits assurance / session-revoked events.
	caepTx := NewCAEPTransmitter(d.Signer, jwtIssuer, os.Getenv("RISK_EVENTS_URL"),
		os.Getenv(httpx.EnvInternalAuthSecret), d.Logger)
	analyzer := NewDeviceAnalyzer(d.Store, d.Logger, caepTx)

	// Risk-evaluation stage client. Prefer an injected evaluator (tests); else
	// build an HTTP client from risk-service's base (derived from RISK_EVENTS_URL).
	// Unset → nil → the stage fails open (no risk inputs).
	riskEval := d.Risk
	if riskEval == nil {
		if base := RiskBaseURL(os.Getenv("RISK_EVENTS_URL")); base != "" {
			if rc, err := NewHTTPRiskClient(d.Logger, base); err != nil {
				d.Logger.Error("risk_client_init_failed", "err", err)
			} else {
				riskEval = rc
			}
		}
	}
	oidc := &OIDCHandlers{
		Store:           d.Store,
		Logger:          d.Logger,
		Issuer:          d.Issuer,
		Signer:          d.Signer,
		Verifier:        verifier,
		JWTIssuer:       jwtIssuer,
		Authenticator:   d.Authenticator,
		DevAutologin:    d.DevAutologin,
		StepUps:         stepUps,
		Protection:      protection,
		Analyzer:        analyzer,
		CAEP:            caepTx,
		StepUpFreshness: d.StepUpFreshness,
		FlowEngine:      d.FlowEngine,
		Risk:            riskEval,
	}
	social := &SocialHandlers{Store: d.Store, Logger: d.Logger, Issuer: d.Issuer, Providers: d.SocialProviders, Analyzer: analyzer}
	login := &LoginHandlers{Store: d.Store, Logger: d.Logger, Issuer: d.Issuer}
	phone := NewPhoneLoginHandlers(d.Store, d.Logger, d.Issuer)
	phone.Analyzer = analyzer
	dev := &DeveloperConsoleHandlers{Store: d.Store, Logger: d.Logger, Issuer: d.Issuer}
	admin := NewAdminConsoleHandlers(d.Store, d.Logger, d.Issuer, d.AdminEmails, d.RootEmails, d.CORSOrigins)
	admin.StepUps = stepUps
	admin.Events = d.Events
	admin.Health = d.Health
	mdlVer := d.MDLVerifier
	if mdlVer == nil {
		mdlVer = NewHTTPMDLProofVerifier(os.Getenv("ID_ISSUER"), os.Getenv("ID_JWKS_URL"), d.Logger)
	}
	idClient := d.IDClient
	if idClient == nil {
		idClient = NewHTTPIDClient(os.Getenv("ID_ISSUER"))
	}
	signup := &SignupConsoleHandlers{Store: d.Store, Logger: d.Logger, Issuer: d.Issuer, StepUps: stepUps,
		Verifier:    smsx.New(smsx.ConfigFromEnv(), d.Logger),
		MDLVerifier: mdlVer, IDClient: idClient}
	users := &UserHandlers{Store: d.Store, Logger: d.Logger}
	sessions := &SessionHandlers{Store: d.Store, Logger: d.Logger}
	advice := &AdviceHandlers{Store: d.Store, Logger: d.Logger}

	mux := http.NewServeMux()

	// Liveness probe. No tenant header required.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// X-Auth favicon for the hosted pages — /favicon.ico is the browser's
	// automatic probe; /favicon.svg is the one the head link references.
	mux.HandleFunc("GET /favicon.ico", Favicon)
	mux.HandleFunc("GET /favicon.svg", Favicon)

	// The public OIDC surface is CORS-enabled for configured SPA origins;
	// fetch-able routes additionally answer OPTIONS preflights (the /userinfo
	// Authorization header triggers one). /authorize is top-level navigation
	// and needs no CORS.
	withCORS := func(h http.HandlerFunc) http.Handler { return corsHandler(d.CORSOrigins, d.Store, h) }

	// OIDC discovery — static JSON.
	mux.Handle("GET /.well-known/oauth-authorization-server", withCORS(oidc.OAuthMetadata))
	mux.Handle("GET /.well-known/openid-configuration", withCORS(oidc.OIDCMetadata))

	// JWKS — canonical route per ARCHITECTURE.md §4.3, plus the conventional
	// well-known alias the discovery documents advertise as jwks_uri.
	mux.Handle("GET /v1/auth/jwks", withCORS(oidc.JWKS))
	mux.Handle("GET /.well-known/jwks.json", withCORS(oidc.JWKS))

	// OIDC / OAuth2 flows — public, no tenant header. /authorize/verify is the
	// OTP-form submission of the second-factor interlude (otp.go) — same-origin
	// browser POST, no CORS needed.
	mux.HandleFunc("GET /authorize", oidc.Authorize)
	mux.HandleFunc("POST /authorize/verify", oidc.AuthorizeVerify)
	// WebAuthn (passkey) register-on-first-use proxies for the step-up page.
	mux.HandleFunc("POST /authorize/webauthn/register/begin", oidc.AuthorizeWebAuthnRegisterBegin)
	mux.HandleFunc("POST /authorize/webauthn/register/finish", oidc.AuthorizeWebAuthnRegisterFinish)
	mux.Handle("POST /token", withCORS(oidc.Token))
	mux.Handle("OPTIONS /token", withCORS(oidc.Token))
	mux.Handle("POST /revoke", withCORS(oidc.Revoke))
	mux.Handle("OPTIONS /revoke", withCORS(oidc.Revoke))
	mux.Handle("GET /userinfo", withCORS(oidc.UserInfo))
	mux.Handle("OPTIONS /userinfo", withCORS(oidc.UserInfo))

	// Social login stubs — public, no tenant header (tenant_id is a query param).
	mux.HandleFunc("GET /v1/social/{provider}/authorize", social.Authorize)
	mux.HandleFunc("GET /v1/social/{provider}/callback", social.Callback)

	// Risk advice: a tenant's backend (authenticated as its confidential OIDC
	// client) maps a transaction_type to the protection level it requires.
	mux.HandleFunc("POST /v1/advice", advice.Advise)

	// Hosted end-user login chooser — public, top-level navigation. A tenant's
	// app sends users here to pick a sign-in method (Google or phone). The Google
	// button forwards to the social leg above; the phone button to /login/phone.
	mux.HandleFunc("GET /login", login.Login)

	// Phone login (primary factor): enter number → SMS OTP → known number logs
	// in, new number creates an account + offers to link Google. POST /login/phone
	// "sends" a code, so it is per-IP rate-limited (PHONE_OTP_RATE, default 10/1h).
	phoneOTPLimit, phoneOTPWindow := 10, time.Hour
	if v := os.Getenv("PHONE_OTP_RATE"); v != "" {
		if n, win, err := ratex.ParseRate(v); err == nil {
			phoneOTPLimit, phoneOTPWindow = n, win
		} else {
			d.Logger.Warn("phone_otp_rate_invalid", "value", v, "err", err)
		}
	}
	phoneSubmit := ratex.Middleware(ratex.New(phoneOTPLimit, phoneOTPWindow),
		func(r *http.Request) string { return clientIP(r) })(http.HandlerFunc(phone.Submit))
	mux.HandleFunc("GET /login/phone", phone.Start)
	mux.Handle("POST /login/phone", phoneSubmit)
	mux.HandleFunc("POST /login/phone/verify", phone.Verify)
	mux.HandleFunc("POST /login/phone/link", phone.LinkStart)
	mux.HandleFunc("POST /login/phone/skip", phone.Skip)
	mux.HandleFunc("GET /login/phone/link/callback", phone.LinkCallback)

	// Hosted developer console: Google sign-in -> OIDC client registration ->
	// built-in code+PKCE round-trip tester with optional ACR selection.
	mux.HandleFunc("GET /dev", dev.Home)
	mux.HandleFunc("GET /dev/", dev.Home)
	mux.HandleFunc("GET /dev/login/google", dev.LoginGoogle)
	mux.HandleFunc("GET /dev/social/callback", dev.SocialCallback)
	mux.HandleFunc("POST /dev/logout", dev.Logout)
	mux.HandleFunc("POST /dev/clients", dev.RegisterClient)
	mux.HandleFunc("GET /dev/oidc/start", dev.StartOIDC)
	mux.HandleFunc("GET /dev/oidc/callback", dev.OIDCCallback)

	// Hosted admin console at /admin is role-aware: a XentraNET staff member on
	// the ADMIN_EMAILS allowlist gets the full all-tenants console (admin.Home);
	// everyone else gets the customer view (signup.Home — the tenant-owner
	// dashboard if signed in, otherwise the self-service landing). currentAdmin
	// has no side effects when the staff cookie is absent, so a plain visitor
	// falls straight through to the owner path.
	adminHome := func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin.currentAdmin(w, r); ok {
			admin.Home(w, r)
			return
		}
		signup.Home(w, r)
	}
	mux.HandleFunc("GET /admin", adminHome)
	mux.HandleFunc("GET /admin/", adminHome)
	mux.HandleFunc("GET /admin/login/google", admin.LoginGoogle)
	mux.HandleFunc("GET /admin/social/callback", admin.SocialCallback)
	mux.HandleFunc("POST /admin/logout", admin.Logout)
	mux.HandleFunc("POST /admin/clients", admin.RegisterClient)
	mux.HandleFunc("POST /admin/clients/delete", admin.DeleteClient)
	// Master-admin drill-down: identities + sessions for one tenant. Staff-only
	// (the handler re-checks currentAdmin); a more specific pattern than
	// GET /admin/. Revoke invalidates any tenant's session.
	mux.HandleFunc("GET /admin/tenants/{id}", admin.TenantDetail)
	mux.HandleFunc("POST /admin/sessions/revoke", admin.RevokeSession)
	mux.HandleFunc("POST /admin/tenants/owner", admin.SetWorkspaceOwner)

	// Self-service signup funnel + tenant-owner dashboard endpoints. The
	// provisioning action (/admin/signup/start) is rate-limited per IP since it
	// is open to anyone with a Google account (SIGNUP_RATE, default 10/1h).
	signupLimit, signupWindow := 10, time.Hour
	if v := os.Getenv("SIGNUP_RATE"); v != "" {
		if n, win, err := ratex.ParseRate(v); err == nil {
			signupLimit, signupWindow = n, win
		} else {
			d.Logger.Warn("signup_rate_invalid", "value", v, "err", err)
		}
	}
	signupStart := ratex.Middleware(ratex.New(signupLimit, signupWindow),
		func(r *http.Request) string { return clientIP(r) })(http.HandlerFunc(signup.SignupStart))
	mux.HandleFunc("GET /admin/signup", signup.SignupLanding)
	mux.Handle("GET /admin/signup/start", signupStart)
	mux.HandleFunc("GET /admin/signup/callback", signup.SignupCallback)
	mux.HandleFunc("GET /admin/owner/login", signup.OwnerLogin)
	mux.HandleFunc("GET /admin/owner/callback", signup.OwnerCallback)
	mux.HandleFunc("POST /admin/owner/logout", signup.OwnerLogout)
	mux.HandleFunc("POST /admin/owner/regenerate-secret", signup.RegenerateSecret)
	mux.HandleFunc("POST /admin/owner/sessions/revoke", signup.RevokeSession)
	mux.HandleFunc("POST /admin/owner/client", signup.UpdateClient)
	mux.HandleFunc("POST /admin/owner/transaction-types", signup.CreateTransactionType)
	mux.HandleFunc("POST /admin/owner/transaction-types/delete", signup.DeleteTransactionType)
	mux.HandleFunc("POST /admin/owner/flows/apply", signup.ApplyFlowTemplate)
	mux.HandleFunc("POST /admin/owner/flows/save", signup.SaveFlow)
	mux.HandleFunc("POST /admin/owner/flows/enable", signup.SetFlowEnabled)
	mux.HandleFunc("POST /admin/owner/flows/validate", signup.ValidateFlow)
	mux.HandleFunc("POST /admin/owner/flows/delete", signup.DeleteFlow)
	mux.HandleFunc("POST /admin/owner/select", signup.OwnerSelect)
	mux.HandleFunc("POST /admin/owner/switch", signup.OwnerSwitch)
	mux.HandleFunc("POST /admin/owner/phone-login", signup.SetPhoneLogin)
	mux.HandleFunc("POST /admin/owner/identities/phone", signup.SetUserPhone)
	mux.HandleFunc("POST /admin/owner/identities/mdl", signup.RecordUserMDL)
	// Self-service mDL enrollment (social-gated): a tenant's user adds their own mDL.
	mux.HandleFunc("GET /enroll/mdl", signup.EnrollMDLStart)
	mux.HandleFunc("GET /enroll/mdl/callback", signup.EnrollMDLCallback)
	mux.HandleFunc("GET /enroll/mdl/page", signup.EnrollMDLPage)
	mux.HandleFunc("GET /enroll/mdl/status", signup.EnrollMDLStatus)
	mux.HandleFunc("POST /admin/owner/identities/remove", signup.RemoveIdentity)
	mux.HandleFunc("GET /admin/owner/download/{asset}", signup.DownloadQuickstart)

	// Tenant-scoped admin endpoints. A dedicated mux under /v1/ lets us wrap only
	// these routes with tenantx.Middleware without firing it for OIDC traffic.
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/users", users.Create)
	v1.HandleFunc("GET /v1/users", users.List)
	v1.HandleFunc("GET /v1/users/{id}", users.Get)
	v1.HandleFunc("PATCH /v1/users/{id}", users.Patch)
	v1.HandleFunc("DELETE /v1/users/{id}", users.Delete)

	v1.HandleFunc("POST /v1/sessions", sessions.Create)
	v1.HandleFunc("GET /v1/sessions/{id}", sessions.Get)
	v1.HandleFunc("POST /v1/sessions/{id}/refresh", sessions.Refresh)
	v1.HandleFunc("POST /v1/sessions/{id}/invalidate", sessions.Invalidate)
	v1.HandleFunc("POST /v1/sessions/{id}/upgrade", sessions.Upgrade)

	// Social routes collide with the /v1/ prefix, so they are registered on the
	// root mux *before* this point. tenantx.Middleware only applies to the
	// tenant-scoped subtree.
	//
	// These user/session admin endpoints have no browser-facing caller — the
	// social login, /dev, and /admin consoles all mutate users/sessions through
	// the in-process Store, and transaction-service uses the /internal/v1
	// alias below. On a deployment where the network is not itself a trust
	// boundary (public Cloud Run ingress, no VPC), V1_INTERNAL_ONLY=true puts
	// the same InternalAuth gate on this public /v1 tree, so an anonymous caller
	// can no longer fabricate users or sessions. Default stays open for
	// back-compat and local dev.
	v1Public := http.Handler(tenantx.Middleware(v1))
	if strings.EqualFold(os.Getenv("V1_INTERNAL_ONLY"), "true") {
		v1Public = httpx.InternalAuth(d.Logger)(v1Public)
	}
	mux.Handle("/v1/users", v1Public)
	mux.Handle("/v1/users/", v1Public)
	mux.Handle("/v1/sessions", v1Public)
	mux.Handle("/v1/sessions/", v1Public)

	// Internal alias: /internal/v1/sessions... → InternalAuth → strip
	// "/internal" → the same tenant-scoped v1 mux. One registration, zero
	// handler duplication. Mounted only on the session subtree so the user
	// CRUD endpoints don't grow an internal alias they have no caller for.
	internalSessions := httpx.InternalAuth(d.Logger)(
		http.StripPrefix("/internal", tenantx.Middleware(v1)))
	mux.Handle("/internal/v1/sessions", internalSessions)
	mux.Handle("/internal/v1/sessions/", internalSessions)

	return httpx.Recover(d.Logger)(httpx.Logging(d.Logger)(mux))
}
