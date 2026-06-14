package internal

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// device_analyzer.go records a device fingerprint at a validation stage and runs
// the (visitorId-only) drift analysis, emitting CAEP security events to
// risk-service via the transmitter (caep.go).
//
// Decision ladder, comparing the fresh fingerprint to the user's history:
//
//   - session fingerprint changed mid-session (a prior signal on the SAME
//     session carried a DIFFERENT fingerprint) → hard anomaly: invalidate the
//     session locally AND emit session-revoked. Models a stolen session cookie
//     replayed on another machine.
//   - first device for this user (no history)        → baseline, no event.
//   - new / changed device (fingerprint unseen)      → assurance-level-change
//     DOWN (aal2→aal1) so the receiver can require step-up.
//   - known device + a step-up just completed        → assurance-level-change
//     UP (aal1→aal2).
//   - known device, plain login                      → no change.
//
// The fingerprint recording and the drift analysis (incl. the local session /
// token-family revocation on a hard anomaly) run synchronously on the request so
// the decision is strictly ordered against the user's history. Only the outbound
// SET delivery to risk-service is detached from the request — see
// CAEPTransmitter.Emit — so a slow or unreachable receiver never adds latency to
// the login.
//
// visitorId-only means we can't tell minor browser drift from a major device
// change, and we don't do device-compliance-change (tamper) here — both need
// component-level signals (see caep.go / the foundation notes).

// DeviceAnalyzer ties device-signal recording to CAEP emission.
type DeviceAnalyzer struct {
	Store  Storage
	Logger *slog.Logger
	CAEP   *CAEPTransmitter // optional; nil → record + log only, no emission
}

// NewDeviceAnalyzer builds an analyzer. caep may be nil (record-only).
func NewDeviceAnalyzer(store Storage, logger *slog.Logger, caep *CAEPTransmitter) *DeviceAnalyzer {
	return &DeviceAnalyzer{Store: store, Logger: logger, CAEP: caep}
}

// Observe records the fingerprint for a validation stage and analyses drift.
// Best-effort — failures are logged, never surfaced to the login. The history
// read, record write, and drift decision run synchronously (local + fast); only
// the SET delivery is detached (CAEPTransmitter.Emit). A nil analyzer or empty
// fingerprint is a no-op.
func (a *DeviceAnalyzer) Observe(r *http.Request, tenantID, userID, sessionID, stage, fp string) {
	if a == nil || fp == "" {
		return
	}
	// Snapshot history BEFORE recording the new observation.
	priors, _ := a.Store.ListDeviceSignalsByUser(tenantID, userID, 100)

	ds := DeviceSignal{
		ID: "dvs_" + uuid.NewString(), TenantID: tenantID, UserID: userID, SessionID: sessionID,
		Stage: stage, Fingerprint: fp, IPAddress: clientIP(r), UserAgent: r.UserAgent(), CreatedAt: time.Now().UTC(),
	}
	if err := a.Store.RecordDeviceSignal(ds); err != nil {
		a.Logger.Error("device_signal_record_failed", "err", err, "stage", stage, "tenant_id", tenantID)
	} else {
		a.Logger.Info("device_signal", "stage", stage, "tenant_id", tenantID, "user_id", userID, "fingerprint", fp)
	}
	a.analyze(ds, priors, stage)
}

func (a *DeviceAnalyzer) analyze(ds DeviceSignal, priors []DeviceSignal, stage string) {
	// Hard anomaly: same session, different fingerprint than before.
	if ds.SessionID != "" {
		for _, p := range priors {
			if p.SessionID == ds.SessionID && p.Fingerprint != ds.Fingerprint {
				a.Logger.Warn("device_fp_session_anomaly", "tenant_id", ds.TenantID, "user_id", ds.UserID, "session_id", ds.SessionID)
				if err := revokeSession(a.Store, ds.TenantID, ds.SessionID); err != nil && err != ErrNotFound {
					a.Logger.Error("device_fp_revoke_failed", "err", err, "session_id", ds.SessionID)
				}
				// Killing the session cookie isn't enough: a replayed session may
				// already hold a live refresh-token family. Revoke every family
				// minted against this session (§10.1 theft response).
				if n, err := a.Store.RevokeTokenFamiliesBySession(ds.TenantID, ds.SessionID); err != nil {
					a.Logger.Error("device_fp_family_revoke_failed", "err", err, "session_id", ds.SessionID)
				} else if n > 0 {
					a.Logger.Warn("device_fp_families_revoked", "session_id", ds.SessionID, "tokens", n)
				}
				uri, ev := SessionRevoked(ds.TenantID, ds.UserID, ds.SessionID,
					"device fingerprint changed within session (possible session replay)", ds.Fingerprint)
				a.emit(ds, uri, ev)
				return
			}
		}
	}

	known := false
	for _, p := range priors {
		if p.Fingerprint == ds.Fingerprint {
			known = true
			break
		}
	}
	stepUp := stage == DeviceStageOTP || stage == DeviceStagePasskey

	switch {
	case len(priors) == 0:
		a.Logger.Info("device_fp_baseline", "tenant_id", ds.TenantID, "user_id", ds.UserID)
	case !known:
		uri, ev := AssuranceLevelChange(ds.TenantID, ds.UserID, ds.SessionID,
			AAL1, AAL2, "decrease", "new or changed device fingerprint", ds.Fingerprint)
		a.emit(ds, uri, ev)
	case stepUp:
		uri, ev := AssuranceLevelChange(ds.TenantID, ds.UserID, ds.SessionID,
			AAL2, AAL1, "increase", "step-up validated on a known device", ds.Fingerprint)
		a.emit(ds, uri, ev)
	default:
		// known device, plain login — no assurance change.
	}
}

func (a *DeviceAnalyzer) emit(ds DeviceSignal, uri string, ev map[string]any) {
	if a.CAEP == nil {
		a.Logger.Info("caep_event_skipped_no_transmitter", "event", uri, "tenant_id", ds.TenantID, "user_id", ds.UserID)
		return
	}
	a.CAEP.Emit(ds.TenantID, ds.UserID, ds.SessionID, uri, ev)
}
