package ratelimit

import (
	"hash/fnv"
	"log"
	"sync"
	"time"

	"webtraffik/internal/db"
)

// ── Rate-limiter / abuse-ban constants ──────────────────────────────────────
const (
	rateThreshold     = 2                // events per second that triggers tracking
	rateSustainWindow = 10 * time.Minute // must sustain high rate for this long to get banned
	BanCooldown       = 1 * time.Hour    // ban duration before the IP is allowed again
	rateShards        = 64               // number of rate-map shards (must be power of 2)
	rateGCInterval    = 5 * time.Minute  // how often we sweep stale rate entries
	rateGCMaxAge      = 30 * time.Second // evict rate entries idle longer than this
)

// BanEntry is a single active ban record. It is both held in memory and
// persisted to the banned_ips table so it survives restarts.
type BanEntry struct {
	IP        string    `json:"ip"`
	Port      string    `json:"port"`
	Service   string    `json:"service"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ipPortKey is the composite key used in the per-IP/port tracker.
type ipPortKey struct {
	ip   string
	port string
}

// rateState tracks recent event timestamps for one IP+port combination.
type rateState struct {
	timestamps []time.Time
	highSince  time.Time
}

// rateShard is one shard of the rate map — its own lock + map.
type rateShard struct {
	mu    sync.Mutex
	rates map[ipPortKey]*rateState
}

// Limiter tracks per-IP/port event rates and maintains the active ban set.
//
// The ban map uses a RWMutex — reads (IsBanned) vastly outnumber writes.
// The rate map is sharded across rateShards independent locks so goroutines
// handling connections from different IPs almost never contend.
type Limiter struct {
	banMu sync.RWMutex
	bans  map[ipPortKey]*BanEntry

	shards [rateShards]rateShard

	scanner *scanTracker // port-scan detection

	db              *db.EventDB
	onChange        func()
	onBan           func(banType string) // callback to record ban metrics
	portServiceName func(string) string  // injected to resolve port → service name
}

// New creates a new Limiter. portServiceName resolves a port string to a
// human-readable service name. onBan is called (non-blocking) when a ban is
// created; it receives "auto" or "manual".
func New(portServiceName func(string) string, onBan func(string)) *Limiter {
	rl := &Limiter{
		bans:            make(map[ipPortKey]*BanEntry),
		portServiceName: portServiceName,
		onBan:           onBan,
		scanner:         newScanTracker(),
	}
	for i := range rl.shards {
		rl.shards[i].rates = make(map[ipPortKey]*rateState)
	}
	go rl.rateGC()
	return rl
}

// shard returns the rateShard for the given key.
func (rl *Limiter) shard(key ipPortKey) *rateShard {
	h := fnv.New32a()
	h.Write([]byte(key.ip))
	h.Write([]byte(key.port))
	return &rl.shards[h.Sum32()&(rateShards-1)]
}

// rateGC periodically sweeps stale rate entries that have gone idle.
func (rl *Limiter) rateGC() {
	for {
		time.Sleep(rateGCInterval)
		cutoff := time.Now().Add(-rateGCMaxAge)
		for i := range rl.shards {
			sh := &rl.shards[i]
			sh.mu.Lock()
			for k, st := range sh.rates {
				if len(st.timestamps) == 0 || st.timestamps[len(st.timestamps)-1].Before(cutoff) {
					delete(sh.rates, k)
				}
			}
			sh.mu.Unlock()
		}
	}
}

// SetDB wires the DB reference so the limiter can persist/expire bans.
// Called once from main() after the DB is opened.
func (rl *Limiter) SetDB(d *db.EventDB) {
	rl.db = d
}

// SetOnChange registers a callback invoked whenever the ban set changes.
func (rl *Limiter) SetOnChange(fn func()) {
	rl.onChange = fn
}

// LoadBans seeds the in-memory ban set from the database.
// Called once from main() after the DB is opened. Expired bans are skipped.
func (rl *Limiter) LoadBans() {
	if rl.db == nil {
		return
	}
	entries, err := rl.db.LoadActiveBans()
	if err != nil {
		log.Printf("ratelimit: failed to load bans from DB: %v", err)
		return
	}
	now := time.Now()
	rl.banMu.Lock()
	for _, e := range entries {
		if e.ExpiresAt.Before(now) {
			go rl.db.ExpireBan(e.IP, e.Port)
			continue
		}
		key := ipPortKey{e.IP, e.Port}
		entry := &BanEntry{
			IP:        e.IP,
			Port:      e.Port,
			Service:   e.Service,
			BannedAt:  e.BannedAt,
			ExpiresAt: e.ExpiresAt,
		}
		rl.bans[key] = entry
		remaining := time.Until(e.ExpiresAt)
		go rl.scheduleUnban(key, remaining)
	}
	rl.banMu.Unlock()
	log.Printf("ratelimit: loaded %d active ban(s) from DB", len(entries))
}

// IsBanned returns true if the given IP is currently banned on the given port.
// Hot path — only acquires a read lock on the ban map.
func (rl *Limiter) IsBanned(ip, port string) bool {
	rl.banMu.RLock()
	_, ok := rl.bans[ipPortKey{ip, port}]
	rl.banMu.RUnlock()
	return ok
}

// Record records an event for ip:port and triggers a ban if the sustained-rate
// threshold is breached. Also feeds the port-scan detector.
// Returns false if the IP is already banned (caller should drop the connection).
func (rl *Limiter) Record(ip, port string) bool {
	key := ipPortKey{ip, port}

	// Fast ban check — read lock, non-contending.
	rl.banMu.RLock()
	_, banned := rl.bans[key]
	rl.banMu.RUnlock()
	if banned {
		return false
	}

	// Port-scan detection — independent of the rate limiter.
	rl.scanner.Record(ip, port)

	// Rate tracking — only locks this key's shard.
	sh := rl.shard(key)
	sh.mu.Lock()

	now := time.Now()
	st := sh.rates[key]
	if st == nil {
		st = &rateState{}
		sh.rates[key] = st
	}

	st.timestamps = append(st.timestamps, now)
	cutoff := now.Add(-time.Second)
	i := 0
	for i < len(st.timestamps) && st.timestamps[i].Before(cutoff) {
		i++
	}
	st.timestamps = st.timestamps[i:]

	currentRate := len(st.timestamps)
	shouldBan := false

	if currentRate > rateThreshold {
		if st.highSince.IsZero() {
			st.highSince = now
		}
		if time.Since(st.highSince) >= rateSustainWindow {
			shouldBan = true
			delete(sh.rates, key)
		}
	} else {
		st.highSince = time.Time{}
	}

	sh.mu.Unlock()

	if shouldBan {
		rl.ban(ip, port)
		if rl.onBan != nil {
			rl.onBan("auto")
		}
		return false
	}
	return true
}

// ban creates a BanEntry for ip:port, persists it to the DB, and schedules
// automatic removal after BanCooldown. Must NOT be called with any lock held.
func (rl *Limiter) ban(ip, port string) {
	key := ipPortKey{ip, port}
	now := time.Now()
	entry := &BanEntry{
		IP:        ip,
		Port:      port,
		Service:   rl.portServiceName(port),
		BannedAt:  now,
		ExpiresAt: now.Add(BanCooldown),
	}

	rl.banMu.Lock()
	if _, exists := rl.bans[key]; exists {
		rl.banMu.Unlock()
		return
	}
	rl.bans[key] = entry
	rl.banMu.Unlock()

	log.Printf("ratelimit: BANNED %s on port %s (%s) until %s",
		ip, port, entry.Service, entry.ExpiresAt.UTC().Format(time.RFC3339))

	if rl.db != nil {
		go func() {
			if err := rl.db.PersistBan(entry.IP, entry.Port, entry.Service, entry.BannedAt, entry.ExpiresAt); err != nil {
				log.Printf("ratelimit: failed to persist ban for %s:%s: %v", ip, port, err)
			}
		}()
	}

	if rl.onChange != nil {
		go rl.onChange()
	}

	go rl.scheduleUnban(key, BanCooldown)
}

// scheduleUnban waits for the given duration then removes the ban.
func (rl *Limiter) scheduleUnban(key ipPortKey, after time.Duration) {
	time.Sleep(after)

	rl.banMu.Lock()
	entry, exists := rl.bans[key]
	if !exists {
		rl.banMu.Unlock()
		return
	}
	delete(rl.bans, key)
	rl.banMu.Unlock()

	log.Printf("ratelimit: UNBANNED %s on port %s (cooldown elapsed)", key.ip, key.port)

	if rl.db != nil {
		go func() {
			if err := rl.db.ExpireBan(entry.IP, entry.Port); err != nil {
				log.Printf("ratelimit: failed to expire ban for %s:%s: %v", entry.IP, entry.Port, err)
			}
		}()
	}

	if rl.onChange != nil {
		go rl.onChange()
	}
}

// ActiveBans returns a snapshot of all currently active bans, sorted by
// BannedAt descending (most-recent first).
func (rl *Limiter) ActiveBans() []BanEntry {
	rl.banMu.RLock()
	defer rl.banMu.RUnlock()
	out := make([]BanEntry, 0, len(rl.bans))
	for _, e := range rl.bans {
		out = append(out, *e)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].BannedAt.After(out[j-1].BannedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ActiveScanners returns a snapshot of all IPs currently classified as port
// scanners, delegating to the embedded scanTracker.
func (rl *Limiter) ActiveScanners() []ScannerEntry {
	return rl.scanner.ActiveScanners()
}

// ManualBan immediately bans ip:port for the standard BanCooldown duration.
// Returns false if the IP+port is already banned.
func (rl *Limiter) ManualBan(ip, port string) bool {
	rl.banMu.RLock()
	_, already := rl.bans[ipPortKey{ip, port}]
	rl.banMu.RUnlock()
	if already {
		return false
	}
	if rl.onBan != nil {
		rl.onBan("manual")
	}
	rl.ban(ip, port)
	return true
}

// ManualUnban immediately lifts the ban on ip:port regardless of how it was
// created (automatic or manual). Returns false if no ban existed.
func (rl *Limiter) ManualUnban(ip, port string) bool {
	key := ipPortKey{ip, port}

	rl.banMu.Lock()
	entry, exists := rl.bans[key]
	if !exists {
		rl.banMu.Unlock()
		return false
	}
	delete(rl.bans, key)
	rl.banMu.Unlock()

	// Clear residual rate state.
	sh := rl.shard(key)
	sh.mu.Lock()
	delete(sh.rates, key)
	sh.mu.Unlock()

	log.Printf("ratelimit: UNBANNED (manual) %s on port %s", key.ip, key.port)

	if rl.db != nil {
		go func() {
			if err := rl.db.ExpireBan(entry.IP, entry.Port); err != nil {
				log.Printf("ratelimit: failed to remove manual unban for %s:%s: %v", key.ip, key.port, err)
			}
		}()
	}
	if rl.onChange != nil {
		go rl.onChange()
	}
	return true
}
