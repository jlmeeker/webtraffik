package main

import (
	"log"
	"sync"
	"time"
)

// ── Rate-limiter / abuse-ban constants ──────────────────────────────────────
//
// An IP is banned from a specific port when it exceeds rateThreshold
// events/second for longer than rateSustainWindow.  The ban lasts for
// banCooldown, after which the IP is allowed again and its rate state is
// cleared.
const (
	rateThreshold     = 2                // events per second that triggers tracking
	rateSustainWindow = 10 * time.Minute // must sustain high rate for this long to get banned
	banCooldown       = 1 * time.Hour    // ban duration before the IP is allowed again
)

// BanEntry is a single active ban record.  It is both held in memory and
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
	// timestamps is a sliding window of recent event arrival times.
	// We keep only the last ~2× rateThreshold seconds of entries.
	timestamps []time.Time
	// highSince is the time we first observed the rate exceeding rateThreshold.
	// Zero means the rate is currently below threshold.
	highSince time.Time
}

// RateLimiter tracks per-IP/port event rates and maintains the active ban set.
type RateLimiter struct {
	mu       sync.RWMutex
	rates    map[ipPortKey]*rateState
	bans     map[ipPortKey]*BanEntry // active bans, keyed by ip+port
	db       *eventDB                // for persistence; may be nil during early init
	onChange func()                  // called when the ban set changes (notify WS clients)
}

var appLimiter = &RateLimiter{
	rates: make(map[ipPortKey]*rateState),
	bans:  make(map[ipPortKey]*BanEntry),
}

// SetDB wires the DB reference so the limiter can persist/expire bans.
// Called once from main() after the DB is opened.
func (rl *RateLimiter) SetDB(db *eventDB) {
	rl.mu.Lock()
	rl.db = db
	rl.mu.Unlock()
}

// SetOnChange registers a callback invoked whenever the ban set changes.
// Used to push fresh ban state to WebSocket clients.
func (rl *RateLimiter) SetOnChange(fn func()) {
	rl.mu.Lock()
	rl.onChange = fn
	rl.mu.Unlock()
}

// LoadBans seeds the in-memory ban set from the database.
// Called once from main() after the DB is opened.  Expired bans are skipped.
func (rl *RateLimiter) LoadBans(db *eventDB) {
	entries, err := db.loadActiveBans()
	if err != nil {
		log.Printf("ratelimit: failed to load bans from DB: %v", err)
		return
	}
	now := time.Now()
	rl.mu.Lock()
	for _, e := range entries {
		if e.ExpiresAt.Before(now) {
			// Already expired — clean it up asynchronously
			go db.expireBan(e.IP, e.Port)
			continue
		}
		key := ipPortKey{e.IP, e.Port}
		cp := e // copy
		rl.bans[key] = &cp
		// Schedule expiry in memory
		remaining := time.Until(e.ExpiresAt)
		go rl.scheduleUnban(key, remaining)
	}
	rl.mu.Unlock()
	log.Printf("ratelimit: loaded %d active ban(s) from DB", len(entries))
}

// IsBanned returns true if the given IP is currently banned on the given port.
func (rl *RateLimiter) IsBanned(ip, port string) bool {
	rl.mu.RLock()
	_, ok := rl.bans[ipPortKey{ip, port}]
	rl.mu.RUnlock()
	return ok
}

// Record records an event for ip:port and triggers a ban if the sustained-rate
// threshold is breached.  Returns false if the IP is already banned (caller
// should drop the connection/datagram).
func (rl *RateLimiter) Record(ip, port string) bool {
	key := ipPortKey{ip, port}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Fast path: already banned.
	if _, banned := rl.bans[key]; banned {
		return false
	}

	now := time.Now()
	st := rl.rates[key]
	if st == nil {
		st = &rateState{}
		rl.rates[key] = st
	}

	// Append current time and evict entries older than 1 second.
	st.timestamps = append(st.timestamps, now)
	cutoff := now.Add(-time.Second)
	i := 0
	for i < len(st.timestamps) && st.timestamps[i].Before(cutoff) {
		i++
	}
	st.timestamps = st.timestamps[i:]

	currentRate := len(st.timestamps) // events in the last second

	if currentRate > rateThreshold {
		// Rate is high — record or extend the "high since" marker.
		if st.highSince.IsZero() {
			st.highSince = now
		}
		if time.Since(st.highSince) >= rateSustainWindow {
			// Sustained abuse — ban this IP+port.
			rl.mu.Unlock()
			rl.ban(ip, port)
			rl.mu.Lock()
			return false
		}
	} else {
		// Rate is back below threshold — reset the sustained-high timer.
		st.highSince = time.Time{}
	}

	return true
}

// ban creates a BanEntry for ip:port, persists it to the DB, and schedules
// automatic removal after banCooldown.  Must NOT be called with rl.mu held.
func (rl *RateLimiter) ban(ip, port string) {
	key := ipPortKey{ip, port}
	now := time.Now()
	entry := &BanEntry{
		IP:        ip,
		Port:      port,
		Service:   portServiceName(port),
		BannedAt:  now,
		ExpiresAt: now.Add(banCooldown),
	}

	rl.mu.Lock()
	// Double-check: another goroutine may have banned this IP already.
	if _, exists := rl.bans[key]; exists {
		rl.mu.Unlock()
		return
	}
	rl.bans[key] = entry
	// Clear rate state — no longer needed.
	delete(rl.rates, key)
	onChange := rl.onChange
	db := rl.db
	rl.mu.Unlock()

	log.Printf("ratelimit: BANNED %s on port %s (%s) until %s",
		ip, port, entry.Service, entry.ExpiresAt.UTC().Format(time.RFC3339))

	// Persist to DB (non-blocking).
	if db != nil {
		go func() {
			if err := db.persistBan(entry); err != nil {
				log.Printf("ratelimit: failed to persist ban for %s:%s: %v", ip, port, err)
			}
		}()
	}

	// Notify listeners (e.g. WebSocket hub).
	if onChange != nil {
		go onChange()
	}

	// Schedule automatic unban.
	go rl.scheduleUnban(key, banCooldown)
}

// scheduleUnban waits for the given duration then removes the ban.
func (rl *RateLimiter) scheduleUnban(key ipPortKey, after time.Duration) {
	time.Sleep(after)

	rl.mu.Lock()
	entry, exists := rl.bans[key]
	if !exists {
		rl.mu.Unlock()
		return
	}
	delete(rl.bans, key)
	onChange := rl.onChange
	db := rl.db
	rl.mu.Unlock()

	log.Printf("ratelimit: UNBANNED %s on port %s (cooldown elapsed)", key.ip, key.port)

	if db != nil {
		go func() {
			if err := db.expireBan(entry.IP, entry.Port); err != nil {
				log.Printf("ratelimit: failed to expire ban for %s:%s: %v", entry.IP, entry.Port, err)
			}
		}()
	}

	if onChange != nil {
		go onChange()
	}
}

// ActiveBans returns a snapshot of all currently active bans, sorted by
// BannedAt descending (most-recent first).
func (rl *RateLimiter) ActiveBans() []BanEntry {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	out := make([]BanEntry, 0, len(rl.bans))
	for _, e := range rl.bans {
		out = append(out, *e)
	}
	// Sort most-recent first.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].BannedAt.After(out[j-1].BannedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ManualBan immediately bans ip:port for the standard banCooldown duration,
// using the same path as an automatic abuse-triggered ban.
// Returns false if the IP+port is already banned.
func (rl *RateLimiter) ManualBan(ip, port string) bool {
	rl.mu.RLock()
	_, already := rl.bans[ipPortKey{ip, port}]
	rl.mu.RUnlock()
	if already {
		return false
	}
	rl.ban(ip, port)
	return true
}

// ManualUnban immediately lifts the ban on ip:port regardless of how it was
// created (automatic or manual).  Returns false if no ban existed.
func (rl *RateLimiter) ManualUnban(ip, port string) bool {
	key := ipPortKey{ip, port}

	rl.mu.Lock()
	entry, exists := rl.bans[key]
	if !exists {
		rl.mu.Unlock()
		return false
	}
	delete(rl.bans, key)
	// Also clear any residual rate state so the clock resets cleanly.
	delete(rl.rates, key)
	onChange := rl.onChange
	db := rl.db
	rl.mu.Unlock()

	log.Printf("ratelimit: UNBANNED (manual) %s on port %s", ip, port)

	if db != nil {
		go func() {
			if err := db.expireBan(entry.IP, entry.Port); err != nil {
				log.Printf("ratelimit: failed to remove manual unban for %s:%s: %v", ip, port, err)
			}
		}()
	}
	if onChange != nil {
		go onChange()
	}
	return true
}
