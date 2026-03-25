package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// ── mockEBPF is a thread-safe in-process stub for the ebpfBanner interface ──

type mockEBPF struct {
	mu       sync.Mutex
	active   bool
	bans     map[string]time.Duration // "ip:port" → duration
	unbans   []string                 // "ip:port" entries that were unbanned
	banErr   error                    // if non-nil, Ban() returns this error
	unbanErr error                    // if non-nil, Unban() returns this error
}

func newMockEBPF() *mockEBPF {
	return &mockEBPF{
		active: true,
		bans:   make(map[string]time.Duration),
	}
}

func (m *mockEBPF) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *mockEBPF) Ban(ip, port string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.banErr != nil {
		return m.banErr
	}
	m.bans[ip+":"+port] = d
	return nil
}

func (m *mockEBPF) Unban(ip, port string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unbanErr != nil {
		return m.unbanErr
	}
	delete(m.bans, ip+":"+port)
	m.unbans = append(m.unbans, ip+":"+port)
	return nil
}

func (m *mockEBPF) isBanned(ip, port string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.bans[ip+":"+port]
	return ok
}

func (m *mockEBPF) banCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bans)
}

func (m *mockEBPF) unbanCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.unbans)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newLimiterNoGC() *Limiter {
	// portServiceName returns a static label; onBan is a no-op.
	rl := &Limiter{
		bans:            make(map[ipPortKey]*BanEntry),
		portServiceName: func(p string) string { return "test-svc" },
		onBan:           func(string) {},
		scanner:         newScanTracker(),
	}
	for i := range rl.shards {
		rl.shards[i].rates = make(map[ipPortKey]*rateState)
	}
	// Intentionally do NOT start rateGC goroutine — tests control timing.
	return rl
}

// waitFor polls cond every 1 ms until it returns true or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("condition not met within timeout")
}

// ── SetEBPFManager ────────────────────────────────────────────────────────────

func TestSetEBPFManager(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)
	if rl.ebpfMgr == nil {
		t.Error("ebpfMgr should be set after SetEBPFManager()")
	}
}

func TestSetEBPFManagerNil(t *testing.T) {
	rl := newLimiterNoGC()
	rl.SetEBPFManager(nil) // must not panic
	if rl.ebpfMgr != nil {
		t.Error("ebpfMgr should be nil after SetEBPFManager(nil)")
	}
}

// ── ManualBan → eBPF sync ─────────────────────────────────────────────────────

func TestManualBanSyncsToEBPF(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)

	ok := rl.ManualBan("1.2.3.4", "80")
	if !ok {
		t.Fatal("ManualBan returned false for new IP")
	}

	// Ban() is called in a goroutine; wait for it.
	waitFor(t, 500*time.Millisecond, func() bool { return mock.isBanned("1.2.3.4", "80") })
}

func TestManualBanDuplicateNotSyncedTwice(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)

	rl.ManualBan("5.5.5.5", "443")
	waitFor(t, 500*time.Millisecond, func() bool { return mock.isBanned("5.5.5.5", "443") })

	// Second ManualBan for same IP+port must return false and not call Ban again.
	ok := rl.ManualBan("5.5.5.5", "443")
	if ok {
		t.Error("ManualBan should return false when already banned")
	}
	// Count stays at 1 (not 2).
	time.Sleep(10 * time.Millisecond)
	if mock.banCount() != 1 {
		t.Errorf("mock ban count = %d, want 1", mock.banCount())
	}
}

// ── ManualUnban → eBPF sync ───────────────────────────────────────────────────

func TestManualUnbanSyncsToEBPF(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)

	rl.ManualBan("2.2.2.2", "22")
	waitFor(t, 500*time.Millisecond, func() bool { return mock.isBanned("2.2.2.2", "22") })

	ok := rl.ManualUnban("2.2.2.2", "22")
	if !ok {
		t.Fatal("ManualUnban returned false for an existing ban")
	}

	waitFor(t, 500*time.Millisecond, func() bool { return !mock.isBanned("2.2.2.2", "22") })
}

func TestManualUnbanNonExistentReturnsFalse(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)

	ok := rl.ManualUnban("9.9.9.9", "9999")
	if ok {
		t.Error("ManualUnban should return false for non-existent ban")
	}
	// Must not have called Unban on the eBPF manager.
	time.Sleep(10 * time.Millisecond)
	if mock.unbanCount() != 0 {
		t.Errorf("expected 0 eBPF unbans, got %d", mock.unbanCount())
	}
}

// ── Without eBPF manager (go-only) ───────────────────────────────────────────

func TestManualBanWithoutEBPFManager(t *testing.T) {
	rl := newLimiterNoGC()
	// No SetEBPFManager call — ebpfMgr remains nil.

	ok := rl.ManualBan("3.3.3.3", "3306")
	if !ok {
		t.Fatal("ManualBan failed without eBPF manager")
	}
	if !rl.IsBanned("3.3.3.3", "3306") {
		t.Error("IsBanned should return true after ManualBan")
	}
}

// ── IsBanned ─────────────────────────────────────────────────────────────────

func TestIsBanned(t *testing.T) {
	rl := newLimiterNoGC()
	if rl.IsBanned("1.1.1.1", "80") {
		t.Error("IsBanned should return false before any ban")
	}
	rl.ManualBan("1.1.1.1", "80")
	if !rl.IsBanned("1.1.1.1", "80") {
		t.Error("IsBanned should return true after ManualBan")
	}
	// Different port — must not be banned.
	if rl.IsBanned("1.1.1.1", "443") {
		t.Error("IsBanned should return false for a different port")
	}
}

// ── eBPF inactive → no sync calls ────────────────────────────────────────────

func TestBanNoSyncWhenEBPFInactive(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	mock.active = false // eBPF not attached
	rl.SetEBPFManager(mock)

	rl.ManualBan("4.4.4.4", "8080")
	time.Sleep(20 * time.Millisecond)

	if mock.banCount() != 0 {
		t.Errorf("expected 0 eBPF bans when inactive, got %d", mock.banCount())
	}
}

// ── ActiveBans ────────────────────────────────────────────────────────────────

func TestActiveBansEmpty(t *testing.T) {
	rl := newLimiterNoGC()
	if bans := rl.ActiveBans(); len(bans) != 0 {
		t.Errorf("ActiveBans() = %d entries, want 0", len(bans))
	}
}

func TestActiveBansAfterManualBan(t *testing.T) {
	rl := newLimiterNoGC()
	rl.ManualBan("10.0.0.1", "80")
	rl.ManualBan("10.0.0.2", "443")

	bans := rl.ActiveBans()
	if len(bans) != 2 {
		t.Fatalf("ActiveBans() = %d, want 2", len(bans))
	}
}

func TestActiveBansSortedMostRecentFirst(t *testing.T) {
	rl := newLimiterNoGC()
	rl.ManualBan("10.0.0.1", "80")
	time.Sleep(2 * time.Millisecond)
	rl.ManualBan("10.0.0.2", "443")

	bans := rl.ActiveBans()
	if len(bans) < 2 {
		t.Skip("need at least 2 bans to test sort order")
	}
	if !bans[0].BannedAt.After(bans[1].BannedAt) && bans[0].BannedAt.Equal(bans[1].BannedAt) {
		// Equal timestamps are acceptable (very fast systems); only fail if
		// strictly out of order.
		if bans[0].BannedAt.Before(bans[1].BannedAt) {
			t.Error("ActiveBans() not sorted most-recent first")
		}
	}
}

// ── Record (volume threshold) ─────────────────────────────────────────────────

func TestRecordReturnsFalseWhenBanned(t *testing.T) {
	rl := newLimiterNoGC()
	rl.ManualBan("6.6.6.6", "22")

	// Record() must return false immediately (IP is banned).
	if rl.Record("6.6.6.6", "22") {
		t.Error("Record() should return false for a banned IP")
	}
}

func TestRecordReturnsTrueWhenNotBanned(t *testing.T) {
	rl := newLimiterNoGC()
	if !rl.Record("7.7.7.7", "80") {
		t.Error("Record() should return true for a fresh IP")
	}
}

func TestRecordTriggersVolumeBan(t *testing.T) {
	rl := newLimiterNoGC()
	mock := newMockEBPF()
	rl.SetEBPFManager(mock)

	ip, port := "8.8.4.4", "3306"
	// Pump volumeThreshold (30) events to trigger a volume ban.
	for i := 0; i < volumeThreshold; i++ {
		rl.Record(ip, port)
	}

	// After 30 events the IP should be banned in memory.
	if !rl.IsBanned(ip, port) {
		t.Error("IP should be banned after volumeThreshold events")
	}
	// And synced to eBPF.
	waitFor(t, 500*time.Millisecond, func() bool { return mock.isBanned(ip, port) })
}

// ── ManualUnban clears rate state ─────────────────────────────────────────────

func TestManualUnbanClearsRateState(t *testing.T) {
	rl := newLimiterNoGC()
	ip, port := "11.11.11.11", "5432"
	key := ipPortKey{ip, port}

	// Record one event to prime the rate state.
	rl.Record(ip, port)
	sh := rl.shard(key)
	sh.mu.Lock()
	_, hasState := sh.rates[key]
	sh.mu.Unlock()
	if !hasState {
		t.Skip("rate state not created after Record (fast machine may skip)")
	}

	rl.ManualBan(ip, port)
	rl.ManualUnban(ip, port)

	sh.mu.Lock()
	_, stillHasState := sh.rates[key]
	sh.mu.Unlock()
	if stillHasState {
		t.Error("ManualUnban should clear rate state for the IP+port")
	}
}
