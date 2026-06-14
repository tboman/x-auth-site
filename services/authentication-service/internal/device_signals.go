package internal

import "time"

// device_signals.go captures a client-side device fingerprint (FingerprintJS
// visitorId) at each login/authorize validation stage and appends it to the
// device-signal log for later analysis.
//
// The fingerprint is produced in the browser by FingerprintJS OSS (loaded from
// CDN on the hosted pages — see deviceFPScript) and submitted as `device_fp`:
//   - social login  → the /login Google link carries it into the social leg,
//     and completeLogin records it once the session+user exist;
//   - SMS OTP        → the hosted code form posts it to the verify step;
//   - passkey/FIDO2  → the hosted assertion form posts it to the verify step.
//
// Recording is best-effort: a failure here never blocks a login.

// Device-signal validation stages.
const (
	DeviceStageSocial  = "social"
	DeviceStageOTP     = "otp"
	DeviceStagePasskey = "passkey"
)

// DeviceSignal is one immutable device observation.
type DeviceSignal struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Stage       string    `json:"stage"`
	Fingerprint string    `json:"fingerprint"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// stageForMethod maps an authenticator method to its device-signal stage.
func stageForMethod(method string) string {
	if method == "fido2" {
		return DeviceStagePasskey
	}
	return DeviceStageOTP
}

// deviceFPScript is the shared client snippet injected into hosted pages that
// capture a fingerprint. It loads FingerprintJS OSS from CDN, computes the
// visitorId, and then:
//   - sets it on every <input data-device-fp> (hidden field posted with a form), and
//   - appends ?device_fp=<id> to every <a data-device-fp> href (the social leg link).
//
// Robustness: a link click before the fingerprint resolves is intercepted (wait
// then navigate); a form submit before it's filled is intercepted likewise. If
// FingerprintJS fails to load (offline, blocked), everything proceeds with an
// empty fingerprint — the device signal is simply skipped server-side.
//
// ⚠️ This loads a third-party script (openfpcdn.io) on the auth domain. If a
// Content-Security-Policy is ever added, allow that origin in script-src.
const deviceFPScript = `
<script type="module">
const fpPromise = (async () => {
  try {
    const FP = (await import('https://openfpcdn.io/fingerprintjs/v4')).default;
    const agent = await FP.load();
    return (await agent.get()).visitorId || '';
  } catch (e) { return ''; }
})();
function applyFP(id) {
  document.querySelectorAll('input[data-device-fp]').forEach(el => { if (!el.value) el.value = id; });
  document.querySelectorAll('a[data-device-fp]').forEach(a => {
    try { const u = new URL(a.href, location.origin); if (id) u.searchParams.set('device_fp', id); a.href = u.toString(); a.dataset.fpReady = '1'; } catch (e) {}
  });
}
fpPromise.then(applyFP);
document.querySelectorAll('a[data-device-fp]').forEach(a => {
  a.addEventListener('click', async (ev) => {
    if (a.dataset.fpReady) return;
    ev.preventDefault();
    const id = await fpPromise;
    try { const u = new URL(a.href, location.origin); if (id) u.searchParams.set('device_fp', id); location.assign(u.toString()); }
    catch (e) { location.assign(a.href); }
  });
});
document.querySelectorAll('form').forEach(f => {
  const inp = f.querySelector('input[data-device-fp]');
  if (!inp) return;
  f.addEventListener('submit', async (ev) => {
    if (inp.value) return;
    ev.preventDefault();
    inp.value = await fpPromise;
    f.submit();
  });
});
</script>`
