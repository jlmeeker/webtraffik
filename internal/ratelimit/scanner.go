package ratelimit

import (
	"sync"
	"time"
)

// ── Port-scan detection constants ────────────────────────────────────────────

const (
	// ScanPortThreshold is the minimum number of distinct destination ports an
	// IP must hit within ScanWindow to be classified as a port scanner.
	ScanPortThreshold = 5

	// ScanWindow is the rolling time window over which distinct port hits are
	// counted. Port hits older than this are forgotten.
	ScanWindow = 10 * time.Minute

	// ScanDisplayDuration is how long a detected scanner remains visible in the
	// panel after it was first detected (independent of whether it keeps hitting
	// ports). Resets if new ports are seen after the initial detection.
	ScanDisplayDuration = 1 * time.Hour

	// scanGCInterval is how often the scanner GC sweep runs.
	scanGCInterval = 2 * time.Minute
)

// ScannerEntry is a snapshot of one detected port scanner, returned by
// ActiveScanners for the /api/scanners endpoint.
type ScannerEntry struct {
	IP         string    `json:"ip"`
	PortCount  int       `json:"port_count"`
	DetectedAt time.Time `json:"detected_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// scanState holds the in-progress or detected state for one source IP.
type scanState struct {
	// portHits maps dst_port → most-recent hit time within the window.
	portHits map[string]time.Time

	// detectedAt is the time at which the IP first crossed ScanPortThreshold.
	// Zero until detection fires.
	detectedAt time.Time

	// expiresAt is when this entry should stop showing in the panel.
	// Updated (extended) every time a new port is seen after detection.
	expiresAt time.Time

	// lastSeenAt is the most recent time any port was recorded.
	lastSeenAt time.Time
}

// scanTracker detects port-scanning behaviour by watching how many distinct
// destination ports each source IP contacts within a rolling window.
//
// It is intentionally separate from the rate limiter — scan detection and
// flood-rate banning are orthogonal concerns.
type scanTracker struct {
	mu      sync.RWMutex
	entries map[string]*scanState // keyed by src_ip
}

func newScanTracker() *scanTracker {
	st := &scanTracker{
		entries: make(map[string]*scanState),
	}
	go st.gcLoop()
	return st
}

// Record notes that srcIP hit dstPort at the current time.
// Returns true if this event causes the IP to be (newly or already) classified
// as a scanner.
func (st *scanTracker) Record(srcIP, dstPort string) bool {
	now := time.Now()
	cutoff := now.Add(-ScanWindow)

	st.mu.Lock()
	defer st.mu.Unlock()

	s := st.entries[srcIP]
	if s == nil {
		s = &scanState{portHits: make(map[string]time.Time)}
		st.entries[srcIP] = s
	}

	// Evict stale port hits that have fallen outside the rolling window.
	for port, t := range s.portHits {
		if t.Before(cutoff) {
			delete(s.portHits, port)
		}
	}

	// Record this port hit (update timestamp if already seen).
	s.portHits[dstPort] = now
	s.lastSeenAt = now

	distinctPorts := len(s.portHits)

	if distinctPorts >= ScanPortThreshold {
		if s.detectedAt.IsZero() {
			// First time crossing the threshold — mark detected.
			s.detectedAt = now
		}
		// Always extend the expiry whenever we confirm scanning activity.
		s.expiresAt = now.Add(ScanDisplayDuration)
		return true
	}

	return false
}

// ActiveScanners returns a snapshot of all IPs currently classified as
// scanners whose display expiry has not yet elapsed, sorted by port count
// descending (most active scanners first).
func (st *scanTracker) ActiveScanners() []ScannerEntry {
	now := time.Now()

	st.mu.RLock()
	defer st.mu.RUnlock()

	out := make([]ScannerEntry, 0)
	for ip, s := range st.entries {
		if s.detectedAt.IsZero() || now.After(s.expiresAt) {
			continue
		}
		out = append(out, ScannerEntry{
			IP:         ip,
			PortCount:  len(s.portHits),
			DetectedAt: s.detectedAt,
			ExpiresAt:  s.expiresAt,
			LastSeenAt: s.lastSeenAt,
		})
	}

	// Sort by port count desc, then by detected time asc (stable ordering).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.PortCount < b.PortCount ||
				(a.PortCount == b.PortCount && a.DetectedAt.After(b.DetectedAt)) {
				out[j-1], out[j] = out[j], out[j-1]
			} else {
				break
			}
		}
	}

	return out
}

// gcLoop periodically evicts entries that are fully expired and have no
// recent activity — keeping memory bounded even under sustained scanning.
func (st *scanTracker) gcLoop() {
	for {
		time.Sleep(scanGCInterval)
		now := time.Now()
		cutoff := now.Add(-ScanWindow)

		st.mu.Lock()
		for ip, s := range st.entries {
			// Evict stale port hits first.
			for port, t := range s.portHits {
				if t.Before(cutoff) {
					delete(s.portHits, port)
				}
			}
			// Remove the entry entirely if it has expired from display and has
			// no remaining port hits in the window.
			expired := !s.expiresAt.IsZero() && now.After(s.expiresAt)
			noActivity := len(s.portHits) == 0
			if expired && noActivity {
				delete(st.entries, ip)
			}
		}
		st.mu.Unlock()
	}
}
