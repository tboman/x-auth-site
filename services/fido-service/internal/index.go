package internal

import (
	"sort"
	"strings"

	"github.com/google/uuid"
)

// SnapshotMeta describes the MDS blob an Index was built from.
type SnapshotMeta struct {
	Number     int
	NextUpdate string
	FetchedAt  string // RFC3339
	Source     string // network | cache | store
}

// Index is an immutable, pre-derived view of one MDS snapshot: AAGUID -> profile.
// It is built once per refresh and swapped in atomically (see Manager), so reads
// never lock.
type Index struct {
	profiles map[string]RiskProfile
	order    []string // AAGUIDs sorted by description for stable listing
	meta     SnapshotMeta
}

// buildIndex derives a profile for every entry carrying an AAGUID. Entries
// without an AAGUID (U2F/UAF, identified by aaid) are skipped — this service is
// AAGUID-centric.
func buildIndex(payload *mdsPayload, meta SnapshotMeta) *Index {
	idx := &Index{
		profiles: make(map[string]RiskProfile, len(payload.Entries)),
		meta:     meta,
	}
	for _, e := range payload.Entries {
		key := normalizeAAGUID(e.AaGUID)
		if key == "" {
			continue
		}
		idx.profiles[key] = deriveProfile(key, e)
		idx.order = append(idx.order, key)
	}
	sort.Slice(idx.order, func(i, j int) bool {
		a, b := idx.profiles[idx.order[i]], idx.profiles[idx.order[j]]
		if a.Description != b.Description {
			return a.Description < b.Description
		}
		return a.AAGUID < b.AAGUID
	})
	return idx
}

func (i *Index) lookup(aaguid string) (RiskProfile, bool) {
	p, ok := i.profiles[normalizeAAGUID(aaguid)]
	return p, ok
}

func (i *Index) count() int { return len(i.order) }

// list returns a page of profiles in stable order plus the total count.
func (i *Index) list(offset, limit int) ([]RiskProfile, int) {
	total := len(i.order)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if limit <= 0 || end > total {
		end = total
	}
	out := make([]RiskProfile, 0, end-offset)
	for _, key := range i.order[offset:end] {
		out = append(out, i.profiles[key])
	}
	return out, total
}

// normalizeAAGUID lowercases and canonicalizes an AAGUID to dashed UUID form so
// "EE882879721C..." and "ee882879-721c-..." resolve to the same key.
func normalizeAAGUID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if id, err := uuid.Parse(s); err == nil {
		return id.String()
	}
	return strings.ToLower(s)
}
