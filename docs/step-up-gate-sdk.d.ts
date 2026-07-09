/**
 * X-Auth Step-Up Gate — SDK surface (draft v0.1, 2026-07-08)
 * ============================================================
 *
 * Two packages, one product:
 *   - `@x-auth/gate`          server SDK (Node / edge), uses a SECRET key (sk_…). Scores actions,
 *                             verifies grants, completes headless challenges, validates webhooks.
 *   - `@x-auth/gate-browser`  browser SDK, served as UMD from https://js.x-auth.com/v1 and exposed
 *                             as `window.XAuthGate`. Uses a PUBLISHABLE key (pk_…). Collects a device
 *                             signal and runs the passkey/OTP UI. It can NOT score actions or read grants.
 *
 * Design invariants (mirror the API spec + OpenAPI):
 *   - Additive: you gate individual ACTIONS, never the login path.
 *   - Fail-open: on network error/timeout the server SDK resolves `{ decision: "allow", degraded: true }`
 *     unless `failMode: "closed"`.
 *   - Action-bound proof: `grants.verify` recomputes the action hash and rejects mismatches.
 *   - The wire format is snake_case (see OpenAPI); the SDK exposes camelCase and maps both ways.
 */

// ───────────────────────────────────────────────────────────────────────────
// Shared types
// ───────────────────────────────────────────────────────────────────────────

export type Method = "passkey" | "sms_otp";
export type RiskLevel = "low" | "medium" | "high" | "critical" | "unknown";
export type Decision = "allow" | "challenge" | "block" | "advisory";

export interface Risk {
  /** 0–100. Absent on a degraded (fail-open) score. */
  score?: number;
  level: RiskLevel;
  /** Human-readable reason codes, e.g. ["new_device","amount_anomaly"]. */
  signals?: string[];
}

/** The action you are about to perform. `params` are hashed into the grant's `act` claim. */
export interface GateAction {
  /** Dot-namespaced, your taxonomy: "payment.send", "payout.create", "admin.record.delete". */
  type: string;
  /** Material fields that, if changed, must invalidate the proof (amount, currency, destination…). */
  params: Record<string, unknown>;
  /** Shown on the step-up screen. */
  description?: string;
}

export interface GateUser {
  /** Your stable user id. */
  id: string;
  email?: string;
  /** E.164; enables SMS-OTP. */
  phone?: string;
}

export interface GateContext {
  ip?: string;
  userAgent?: string;
  /** From the browser SDK `xauth.device()`. */
  deviceToken?: string;
  /** What the user already satisfied at login, e.g. "urn:x-auth:acr:pwd". */
  sessionAcr?: string;
}

export interface GateOptions {
  /** "enforce" (default) returns allow/challenge/block. "advisory" returns risk + recommendation only. */
  mode?: "enforce" | "advisory";
  allowedMethods?: Method[];
  /** Present ⇒ hosted-redirect mode (challenge has `hostedUrl`). Absent ⇒ headless mode. */
  returnUrl?: string;
  /** Grant lifetime in seconds (default 300). */
  grantTtl?: number;
  /** Per-call override of the client default. */
  failMode?: "open" | "closed";
  /** Replay-safe key for the gate call (recommended on payment paths). */
  idempotencyKey?: string;
}

export interface GateParams {
  user: GateUser;
  action: GateAction;
  context?: GateContext;
  options?: GateOptions;
}

/** Hosted mode → `hostedUrl`. Headless mode → `passkey` and/or `smsOtp` material. */
export interface Challenge {
  id: string;
  methods: Method[];
  expiresAt: string;
  hostedUrl?: string;
  passkey?: { publicKey: PublicKeyCredentialRequestOptions };
  smsOtp?: { sentTo: string; length: number };
}

// Discriminated gate result — switch on `.decision`.
export type GateResult = AllowResult | ChallengeResult | BlockResult | AdvisoryResult;

export interface AllowResult {
  decision: "allow";
  risk: Risk;
  /** Ready-to-verify grant. Absent on a degraded fail-open allow. */
  grant?: string;
  grantId?: string;
  /** true ⇒ scored under fail-open degradation (API was slow/unreachable). */
  degraded: boolean;
}
export interface ChallengeResult { decision: "challenge"; risk: Risk; challenge: Challenge; }
export interface BlockResult { decision: "block"; risk: Risk; reason: string; }
export interface AdvisoryResult { decision: "advisory"; risk: Risk; recommended: "allow" | "challenge" | "block"; }

// ───────────────────────────────────────────────────────────────────────────
// Server SDK — `@x-auth/gate`
// ───────────────────────────────────────────────────────────────────────────

export interface XAuthOptions {
  /** Default "https://api.x-auth.com". */
  baseUrl?: string;
  /** Pinned API version. Default "2026-07-08". */
  apiVersion?: string;
  /** Fail-open threshold; also the request timeout. Default 3000. */
  timeoutMs?: number;
  /** Global default; overridable per gate() call. Default "open". */
  failMode?: "open" | "closed";
  /** Inject a fetch impl (Cloudflare Workers, Deno, tests). */
  fetch?: typeof fetch;
  /** JWKS cache TTL in seconds for local verification. Default 3600. */
  jwksCacheTtl?: number;
}

export interface VerifyOptions {
  /** The action you are about to perform — recomputed and compared to the grant's `act`. */
  expectedAction: { type: string; params: Record<string, unknown> };
  /** Enforce single-use locally by supplying a seen-jti store. Optional. */
  jtiStore?: JtiStore;
}

export interface JtiStore {
  /** Return true if `jti` was already used; otherwise record it and return false. */
  checkAndSet(jti: string, expEpoch: number): Promise<boolean>;
}

export interface VerifiedGrant {
  active: boolean;
  /** true when the grant's bound action equals `expectedAction`. */
  actionMatches: boolean;
  sub?: string;
  acr?: string;
  amr?: string[];
  risk?: number;
  exp?: string;
  jti?: string;
  /** Present when `active` is false, e.g. "expired" | "already_consumed" | "bad_signature". */
  reason?: string;
}

export interface Grants {
  /**
   * Verify a grant LOCALLY against the cached JWKS (no network on the happy path).
   * Checks signature, iss/aud/exp, recomputes the action hash vs `expectedAction`, and — if a
   * `jtiStore` is supplied — enforces single-use. This is the recommended execute-path check:
   * your action never depends on X-Auth being reachable.
   */
  verify(grant: string, opts: VerifyOptions): Promise<VerifiedGrant>;

  /**
   * Server-side introspection. Consumes the single-use grant on X-Auth's side and returns whether
   * it matches `expectedAction`. Easier on-ramp, but re-adds a runtime network call.
   */
  introspect(grant: string, opts?: Partial<VerifyOptions>): Promise<VerifiedGrant>;

  /** Parse a hosted-mode return URL/query into { grant, grantId, error }. */
  parseReturn(input: string | URLSearchParams | Record<string, string>): {
    grant?: string;
    grantId?: string;
    error?: "abandoned" | "failed" | "expired";
    challengeId?: string;
  };
}

export interface ChallengeStatus {
  id: string;
  status: "pending" | "completed" | "failed" | "expired";
  grantId?: string;
}

export type ChallengeVerifyResult =
  | { status: "completed"; grant: string; grantId: string }
  | { status: "failed"; attemptsRemaining: number };

export interface Challenges {
  /** Poll a headless challenge. */
  retrieve(id: string): Promise<ChallengeStatus>;
  /** Submit an OTP code or a WebAuthn assertion to complete a headless challenge. */
  verify(
    id: string,
    input: { method: "sms_otp"; code: string } | { method: "passkey"; assertion: unknown }
  ): Promise<ChallengeVerifyResult>;
}

export interface WebhookEvent {
  id: string;
  type: "challenge.completed" | "challenge.failed" | "challenge.expired";
  created: string;
  data: { challengeId: string; grantId?: string; actionType: string; sub: string };
}

export interface Webhooks {
  /**
   * Verify the `X-Auth-Signature` header and return the typed event.
   * Throws `XAuthSignatureError` on mismatch or stale timestamp.
   */
  constructEvent(payload: string | Buffer, signatureHeader: string, secret: string): WebhookEvent;
}

export declare class XAuth {
  constructor(secretKey: string, options?: XAuthOptions);
  /** Evaluate one action. Fail-open per `options.failMode`/client default. */
  gate(params: GateParams): Promise<GateResult>;
  readonly grants: Grants;
  readonly challenges: Challenges;
  readonly webhooks: Webhooks;
}

// Errors
export declare class XAuthError extends Error { type: string; status?: number; param?: string; }
export declare class XAuthSignatureError extends XAuthError {}

// ───────────────────────────────────────────────────────────────────────────
// Browser SDK — `@x-auth/gate-browser`  (UMD at https://js.x-auth.com/v1 → window.XAuthGate)
// ───────────────────────────────────────────────────────────────────────────

export interface BrowserOptions {
  baseUrl?: string; // default https://api.x-auth.com
  /** Container for the built-in OTP UI when using mountChallenge. */
  appearance?: { theme?: "auto" | "light" | "dark"; accentColor?: string };
}

export interface MountResult {
  grant: string;
  grantId: string;
}

export interface XAuthGateClient {
  /**
   * Collect a privacy-preserving device signal token. Pass the result to the server as
   * `context.deviceToken`. Cached in the browser; call once per page/session.
   */
  device(): Promise<string>;

  /**
   * HEADLESS mode helper: given the `challenge` object your server returned, render the built-in
   * passkey/OTP UI into `target` and resolve with a verified `grant` once the user completes it.
   * Internally calls navigator.credentials.get() for passkey and POSTs the OTP/assertion to
   * /v1/challenges/{id}/verify with the publishable key.
   */
  mountChallenge(challenge: Challenge, target?: HTMLElement | string): Promise<MountResult>;

  /**
   * HEADLESS + custom UI: run just the WebAuthn assertion for a passkey challenge and return the
   * raw credential to POST yourself. Use when you don't want the built-in UI.
   */
  getPasskeyAssertion(challenge: Challenge): Promise<Credential | null>;

  /** HOSTED mode helper: navigate the browser to `challenge.hostedUrl`. */
  redirectToChallenge(challenge: Challenge): void;
}

/** Factory. `publishableKey` is a pk_live_/pk_test_ key — safe to ship to the browser. */
export declare function XAuthGate(publishableKey: string, options?: BrowserOptions): XAuthGateClient;

declare global {
  interface Window {
    XAuthGate: typeof XAuthGate;
  }
}

/* ===========================================================================
 * USAGE
 * ===========================================================================
 *
 * ── Hosted-redirect mode (simplest; the "10 lines") ────────────────────────
 *
 *   // server: before a risky action
 *   import { XAuth } from "@x-auth/gate";
 *   const xauth = new XAuth(process.env.XAUTH_SECRET_KEY);
 *
 *   const gate = await xauth.gate({
 *     user:    { id: user.id, phone: user.phone },
 *     action:  { type: "payment.send",
 *                params: { amount: 4200, currency: "USD", destination: payeeId } },
 *     context: { ip: req.ip, userAgent: req.get("user-agent"), deviceToken: req.body.deviceToken },
 *     options: { returnUrl: "https://app.example.com/pay/confirm" },
 *   });
 *
 *   if (gate.decision === "block")     return res.status(403).send("Blocked");
 *   if (gate.decision === "challenge") return res.redirect(gate.challenge.hostedUrl!);
 *   // "allow" → fall through to execute
 *
 *   // server: on the return_url — introspect() consumes the single-use grant so a
 *   // refreshed/replayed ?grant= URL can't re-run the action. (grants.verify is the
 *   // local, no-network check but needs a jtiStore to be replay-safe.)
 *   const { grant, error } = xauth.grants.parseReturn(req.query as Record<string, string>);
 *   if (error || !grant) return res.status(403).send("Re-auth required");
 *   const v = await xauth.grants.introspect(grant, {
 *     expectedAction: { type: "payment.send",
 *                       params: { amount: 4200, currency: "USD", destination: payeeId } },
 *   });
 *   if (!v.active || !v.actionMatches) return res.status(403).send("Invalid");
 *   await executePayment(payeeId, 4200);
 *
 * ── Browser: device signal (once) ──────────────────────────────────────────
 *
 *   <script src="https://js.x-auth.com/v1"></script>
 *   <script type="module">   // type="module" so top-level await parses
 *     const xauth = window.XAuthGate("pk_live_…");
 *     const deviceToken = await xauth.device();   // send with the action request
 *   </script>
 *
 * ── Headless mode (SPA, no redirect) ───────────────────────────────────────
 *
 *   // server returns the challenge object to the client instead of redirecting
 *   const gate = await xauth.gate({ user, action, context, options: { mode: "enforce" } });
 *   if (gate.decision === "challenge") return res.json({ challenge: gate.challenge });
 *
 *   // client completes it with the built-in UI, gets a grant, sends it back to execute
 *   const xauth = window.XAuthGate("pk_live_…");
 *   const { grant } = await xauth.mountChallenge(challenge, "#step-up");
 *   await fetch("/pay/execute", { method: "POST", body: JSON.stringify({ grant }) });
 *
 * ── Webhooks ───────────────────────────────────────────────────────────────
 *
 *   const event = xauth.webhooks.constructEvent(rawBody, req.headers["x-auth-signature"], whSecret);
 *   if (event.type === "challenge.completed") { /* record audit, update UI * / }
 *
 * ===========================================================================
 */
