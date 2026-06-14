package internal

import (
	"html"
	"strings"
	"time"
)

// sessions_view.go renders the session-management blocks shared by the
// master-admin tenant drill-down and the owner dashboard: a table of a tenant's
// active sessions (who is logged in, their risk + step-up state) and a live
// "in-progress step-up" list (who is mid-OTP on an /authorize call right now).

// revokeSession invalidates a session (tenant-scoped). Idempotent: an already
// invalidated session is left untouched. Returns ErrNotFound when the session
// doesn't exist in the tenant.
func revokeSession(store Storage, tenantID, sessionID string) error {
	sess, err := store.GetSession(tenantID, sessionID)
	if err != nil {
		return err
	}
	if sess.InvalidatedAt != nil {
		return nil
	}
	now := time.Now().UTC()
	sess.InvalidatedAt = &now
	_, err = store.UpdateSession(sess)
	return err
}

// emailIndex maps user id → email for labelling sessions/step-ups by who they
// belong to, built from a tenant's user list.
func emailIndex(users []User) map[string]string {
	m := make(map[string]string, len(users))
	for _, u := range users {
		m[u.ID] = u.Email
	}
	return m
}

// userLabel renders the user's email when known, falling back to the opaque id.
func userLabel(userID string, emailByUser map[string]string) string {
	if e := emailByUser[userID]; e != "" {
		return html.EscapeString(e) + ` <span class="muted">(` + html.EscapeString(userID) + `)</span>`
	}
	return `<code>` + html.EscapeString(userID) + `</code>`
}

// sessionStatus classifies a session for display.
func sessionStatus(sess Session, now time.Time) (label, color string) {
	switch {
	case sess.InvalidatedAt != nil:
		return "revoked", "var(--danger)"
	case now.After(sess.ExpiresAt):
		return "expired", "var(--muted)"
	default:
		return "active", "var(--accent)"
	}
}

// sessionsPanel renders the active-sessions table. revokeCell, when non-nil,
// adds a trailing action column; it returns the cell's inner HTML for a session
// (typically a revoke form) or "" for none.
func sessionsPanel(sessions []Session, emailByUser map[string]string, now time.Time, revokeCell func(Session) string) string {
	withRevoke := revokeCell != nil
	var b strings.Builder
	b.WriteString(`<h2 style="margin-top:28px">Sessions</h2>
<p class="muted">Active and recent sign-in sessions for this workspace.</p>
<div class="panel"><table>
<thead><tr><th>User</th><th>Risk</th><th>Step-up</th><th>Created (UTC)</th><th>Expires (UTC)</th><th>Status</th>`)
	if withRevoke {
		b.WriteString(`<th></th>`)
	}
	b.WriteString(`</tr></thead><tbody>`)

	if len(sessions) == 0 {
		span := "6"
		if withRevoke {
			span = "7"
		}
		b.WriteString(`<tr><td colspan="` + span + `" class="muted">No sessions.</td></tr>`)
	} else {
		for _, sess := range sessions {
			label, color := sessionStatus(sess, now)
			stepUp := "no"
			if sess.StepUpCompleted {
				stepUp = "completed"
			}
			b.WriteString(`<tr>`)
			b.WriteString(`<td>` + userLabel(sess.UserID, emailByUser) + `</td>`)
			b.WriteString(`<td>` + html.EscapeString(sess.RiskLevel) + `</td>`)
			b.WriteString(`<td>` + stepUp + `</td>`)
			b.WriteString(`<td class="muted">` + sess.CreatedAt.UTC().Format(time.RFC3339) + `</td>`)
			b.WriteString(`<td class="muted">` + sess.ExpiresAt.UTC().Format(time.RFC3339) + `</td>`)
			b.WriteString(`<td><span style="color:` + color + `">` + label + `</span></td>`)
			if withRevoke {
				cell := revokeCell(sess)
				if cell == "" {
					cell = `<span class="muted">—</span>`
				}
				b.WriteString(`<td>` + cell + `</td>`)
			}
			b.WriteString(`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// deviceSignalsPanel renders the device-fingerprint observations captured at
// each validation stage (social / otp / passkey) — the device-analysis view.
func deviceSignalsPanel(signals []DeviceSignal, emailByUser map[string]string) string {
	var b strings.Builder
	b.WriteString(`<h2 style="margin-top:28px">Device signals</h2>
<p class="muted">Device fingerprints captured at login / step-up validation, newest first.</p>
<div class="panel"><table>
<thead><tr><th>Fingerprint</th><th>Stage</th><th>User</th><th>IP</th><th>Captured (UTC)</th></tr></thead><tbody>`)
	if len(signals) == 0 {
		b.WriteString(`<tr><td colspan="5" class="muted">No device signals yet.</td></tr>`)
	} else {
		for _, ds := range signals {
			b.WriteString(`<tr>`)
			b.WriteString(`<td><code>` + html.EscapeString(ds.Fingerprint) + `</code></td>`)
			b.WriteString(`<td>` + html.EscapeString(ds.Stage) + `</td>`)
			b.WriteString(`<td>` + userLabel(ds.UserID, emailByUser) + `</td>`)
			b.WriteString(`<td class="muted">` + html.EscapeString(ds.IPAddress) + `</td>`)
			b.WriteString(`<td class="muted">` + ds.CreatedAt.UTC().Format(time.RFC3339) + `</td>`)
			b.WriteString(`</tr>`)
		}
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// stepUpsPanel renders the live in-progress step-up attempts — who is mid-OTP
// on an /authorize call right now. Empty renders a quiet "none" note.
func stepUpsPanel(attempts []StepUpAttempt, emailByUser map[string]string, now time.Time) string {
	var b strings.Builder
	b.WriteString(`<h3 style="margin-top:20px">In-progress step-up</h3>`)
	if len(attempts) == 0 {
		b.WriteString(`<p class="muted">No step-up challenges in progress.</p>`)
		return b.String()
	}
	b.WriteString(`<div class="panel"><table>
<thead><tr><th>User</th><th>Method</th><th>Started (UTC)</th><th>Waiting</th></tr></thead><tbody>`)
	for _, a := range attempts {
		waited := now.Sub(a.StartedAt).Truncate(time.Second)
		if waited < 0 {
			waited = 0
		}
		b.WriteString(`<tr>`)
		b.WriteString(`<td>` + userLabel(a.UserID, emailByUser) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(a.Method) + `</td>`)
		b.WriteString(`<td class="muted">` + a.StartedAt.UTC().Format(time.RFC3339) + `</td>`)
		b.WriteString(`<td class="muted">` + waited.String() + `</td>`)
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}
