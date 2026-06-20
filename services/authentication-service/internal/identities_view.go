package internal

import (
	"html"
	"strings"
	"time"
)

// identities_view.go renders the shared "identities" table used by both the
// master-admin per-tenant view (admin_console.go) and the tenant-owner
// dashboard (signup_console.go). One row per identity (user): the canonical
// email anchor plus any phone/passkey anchors, each with a verified marker.
//
// email is read from the user row (the canonical primary anchor); phone and
// passkey come from identity_anchors. Until the validation flows land those two
// columns render empty for every identity — which is exactly the "database is
// prepared, nothing populated yet" state.

// anchorsByUser groups a tenant's anchors by user id.
func anchorsByUser(anchors []IdentityAnchor) map[string][]IdentityAnchor {
	m := make(map[string][]IdentityAnchor, len(anchors))
	for _, a := range anchors {
		m[a.UserID] = append(m[a.UserID], a)
	}
	return m
}

// anchorCell renders all anchors of one type for a user as escaped <code> chips,
// each tagged verified / unverified, or an em dash when the user has none of
// that type.
func anchorCell(userAnchors []IdentityAnchor, typ string) string {
	var b strings.Builder
	n := 0
	for _, a := range userAnchors {
		if a.Type != typ {
			continue
		}
		if n > 0 {
			b.WriteString("<br>")
		}
		mark := `<span style="color:var(--warn)" title="not verified">unverified</span>`
		if a.VerifiedAt != nil {
			mark = `<span style="color:var(--accent)" title="verified">verified</span>`
		}
		b.WriteString(`<code>` + html.EscapeString(a.Value) + `</code> ` + mark)
		n++
	}
	if n == 0 {
		return `<span class="muted">—</span>`
	}
	return b.String()
}

// identityTableRows renders one <tr> per user — email (primary) + phone +
// passkey + created — for a 4-column table. An empty user set yields a single
// "no identities" row (colspan 4).
func identityTableRows(users []User, anchors []IdentityAnchor) string {
	if len(users) == 0 {
		return `<tr><td colspan="5" class="muted">No identities yet.</td></tr>`
	}
	byUser := anchorsByUser(anchors)
	var b strings.Builder
	for _, u := range users {
		ua := byUser[u.ID]
		b.WriteString(`<tr>`)
		b.WriteString(`<td><code>` + html.EscapeString(u.Email) + `</code></td>`)
		b.WriteString(`<td>` + anchorCell(ua, AnchorPhone) + `</td>`)
		b.WriteString(`<td>` + anchorCell(ua, AnchorPasskey) + `</td>`)
		b.WriteString(`<td>` + anchorCell(ua, AnchorMDL) + `</td>`)
		b.WriteString(`<td class="muted">` + html.EscapeString(u.CreatedAt.UTC().Format(time.RFC3339)) + `</td>`)
		b.WriteString(`</tr>`)
	}
	return b.String()
}

// identityTable wraps identityTableRows in the full panel + table shell with the
// standard header row.
func identityTable(users []User, anchors []IdentityAnchor) string {
	return `<div class="panel"><table>
<thead><tr><th>Email (primary)</th><th>Phone</th><th>Passkey</th><th>mDL</th><th>Created (UTC)</th></tr></thead>
<tbody>` + identityTableRows(users, anchors) + `</tbody></table></div>`
}
