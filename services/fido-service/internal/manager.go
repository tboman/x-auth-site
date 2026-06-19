package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Manager owns the MDS lifecycle: it loads a verified snapshot at startup
// (network first, cache/store as warm fallback) and refreshes on a ticker,
// swapping the in-memory Index atomically so reads never block.
type Manager struct {
	log     *slog.Logger
	fetcher *Fetcher
	store   SnapshotStore
	cache   *BlobCache
	now     func() time.Time

	idx     atomic.Pointer[Index]
	lastErr atomic.Pointer[errInfo]
	mu      sync.Mutex // serializes refreshes
}

type errInfo struct {
	msg string
	at  time.Time
}

// NewManager wires the loader. store must be non-nil (use MemSnapshotStore when
// there is no DB); cache may be nil.
func NewManager(log *slog.Logger, fetcher *Fetcher, store SnapshotStore, cache *BlobCache) *Manager {
	return &Manager{
		log:     log,
		fetcher: fetcher,
		store:   store,
		cache:   cache,
		now:     time.Now,
	}
}

// Bootstrap loads an initial snapshot. Network is tried first (freshest); on
// failure it falls back to the Redis cache then the snapshot store so the
// service still serves during an upstream outage. It never returns an error:
// when nothing loads, the risk endpoints answer 503 until the refresher
// succeeds.
func (m *Manager) Bootstrap(ctx context.Context) {
	if err := m.refreshFromNetwork(ctx); err == nil {
		return
	}
	m.log.Warn("mds_network_load_failed_trying_warm_fallback")

	if raw, ok, _ := m.cache.Get(ctx); ok {
		if err := m.loadAndSwap(raw, "cache"); err == nil {
			m.log.Warn("mds_loaded_from_cache_degraded")
			return
		}
	}
	if snap, ok, _ := m.store.Load(ctx); ok {
		if err := m.loadAndSwap(snap.Raw, "store"); err == nil {
			m.log.Warn("mds_loaded_from_store_degraded")
			return
		}
	}
	m.log.Error("mds_bootstrap_failed", "detail", "no network, cache, or stored snapshot available")
}

// RunRefresher re-fetches the blob every interval until ctx is cancelled.
func (m *Manager) RunRefresher(ctx context.Context, interval time.Duration) {
	m.log.Info("mds_refresher_started", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.log.Info("mds_refresher_stopped")
			return
		case <-ticker.C:
			if err := m.refreshFromNetwork(ctx); err != nil {
				m.log.Error("mds_refresh_failed", "err", err)
			}
		}
	}
}

func (m *Manager) refreshFromNetwork(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, err := m.fetcher.Fetch(ctx)
	if err != nil {
		m.recordErr(err)
		return err
	}
	if err := m.loadAndSwap(raw, "network"); err != nil {
		m.recordErr(err)
		return err
	}

	cur := m.idx.Load()
	snap := Snapshot{
		Raw:        raw,
		Number:     cur.meta.Number,
		NextUpdate: cur.meta.NextUpdate,
		EntryCount: cur.count(),
		SHA256:     sha256Hex(raw),
		FetchedAt:  m.now(),
	}
	if err := m.store.Save(ctx, snap); err != nil {
		m.log.Warn("mds_snapshot_save_failed", "err", err) // non-fatal
	}
	if err := m.cache.Set(ctx, raw); err != nil {
		m.log.Warn("mds_cache_set_failed", "err", err) // non-fatal
	}
	m.lastErr.Store(nil)
	m.log.Info("mds_loaded", "blob_number", snap.Number, "entries", snap.EntryCount,
		"next_update", snap.NextUpdate, "source", "network")
	return nil
}

func (m *Manager) loadAndSwap(raw []byte, source string) error {
	payload, err := m.fetcher.VerifyAndParse(raw)
	if err != nil {
		return err
	}
	idx := buildIndex(payload, SnapshotMeta{
		Number:     payload.Number,
		NextUpdate: payload.NextUpdate,
		FetchedAt:  m.now().UTC().Format(time.RFC3339),
		Source:     source,
	})
	m.idx.Store(idx)
	return nil
}

func (m *Manager) recordErr(err error) {
	m.lastErr.Store(&errInfo{msg: err.Error(), at: m.now()})
}

// current returns the live index, or nil before the first successful load.
func (m *Manager) current() *Index { return m.idx.Load() }

// Profile looks up an AAGUID. loaded is false before the first snapshot loads.
func (m *Manager) Profile(aaguid string) (profile RiskProfile, found, loaded bool) {
	idx := m.current()
	if idx == nil {
		return RiskProfile{}, false, false
	}
	p, ok := idx.lookup(aaguid)
	return p, ok, true
}

// ProfileForAttestation builds a profile for an attested AAGUID, falling back to
// an unknown-authenticator base when the AAGUID is absent from the snapshot,
// then layers the attestation flags. loaded is false before the first snapshot.
func (m *Manager) ProfileForAttestation(aaguid string, flags AttestationFlags) (RiskProfile, bool) {
	idx := m.current()
	if idx == nil {
		return RiskProfile{}, false
	}
	p, ok := idx.lookup(aaguid)
	if !ok {
		p = unknownProfile(aaguid)
		if aaguid == "" {
			p.AAGUID = ""
		}
	}
	applyAttestation(&p, flags)
	return p, true
}

// List returns a page of profiles. loaded is false before the first snapshot.
func (m *Manager) List(offset, limit int) (ListResponse, bool) {
	idx := m.current()
	if idx == nil {
		return ListResponse{}, false
	}
	profiles, total := idx.list(offset, limit)
	return ListResponse{
		Total:    total,
		Count:    len(profiles),
		Offset:   offset,
		Profiles: profiles,
	}, true
}

// Status reports snapshot freshness and the last refresh error.
func (m *Manager) Status() MDSStatus {
	var st MDSStatus
	if idx := m.current(); idx != nil {
		st.Loaded = true
		st.BlobNumber = idx.meta.Number
		st.EntryCount = idx.count()
		st.NextUpdate = idx.meta.NextUpdate
		st.FetchedAt = idx.meta.FetchedAt
		st.Source = idx.meta.Source
	}
	if e := m.lastErr.Load(); e != nil {
		st.LastError = e.msg
		st.LastErrorAt = e.at.UTC().Format(time.RFC3339)
	}
	return st
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
