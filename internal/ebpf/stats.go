package ebpf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Stats holds a snapshot of eBPF telemetry counters.
type Stats struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	Interface      string `json:"interface"`
	PacketsPassed  uint64 `json:"packets_passed"`
	PacketsDropped uint64 `json:"packets_dropped"`
	BansActive     int    `json:"bans_active"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
}

// statsCache holds lazily-accumulated totals aggregated from per-CPU counters.
// Using atomic integers avoids a mutex on the hot read path from /api/ebpf/stats.
type statsCache struct {
	passed  atomic.Uint64
	dropped atomic.Uint64
}

// aggregateTelemetry reads the per-CPU telemetry_map and returns the summed
// (passed, dropped) totals. It is called periodically by the stats flush loop.
func (m *Manager) aggregateTelemetry() (passed, dropped uint64, err error) {
	if m.objs == nil {
		return 0, 0, nil
	}

	// Per-CPU arrays return one value slice per CPU.
	var passedVals []uint64
	if err := m.objs.TelemetryMap.Lookup(uint32(0), &passedVals); err != nil {
		return 0, 0, fmt.Errorf("ebpf: telemetry lookup passed: %w", err)
	}
	var droppedVals []uint64
	if err := m.objs.TelemetryMap.Lookup(uint32(1), &droppedVals); err != nil {
		return 0, 0, fmt.Errorf("ebpf: telemetry lookup dropped: %w", err)
	}

	for _, v := range passedVals {
		passed += v
	}
	for _, v := range droppedVals {
		dropped += v
	}
	return passed, dropped, nil
}

// startStatsLoop periodically aggregates per-CPU telemetry into the statsCache.
// It runs until Manager.stopCh is closed.
func (m *Manager) startStatsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p, d, err := m.aggregateTelemetry()
			if err != nil {
				// Non-fatal: map may not be available during detach.
				continue
			}
			m.stats.passed.Store(p)
			m.stats.dropped.Store(d)
		case <-m.stopCh:
			return
		}
	}
}

// Snapshot returns a Stats snapshot for the /api/ebpf/stats endpoint.
func (m *Manager) Snapshot() Stats {
	uptime := int64(0)
	if !m.startedAt.IsZero() {
		uptime = int64(time.Since(m.startedAt).Seconds())
	}

	activeBans := 0
	if m.objs != nil {
		// Count entries in ban_map.
		var k, v interface{}
		iter := m.objs.BanMap.Iterate()
		for iter.Next(&k, &v) {
			activeBans++
		}
	}

	return Stats{
		Enabled:        m.active.Load(),
		Mode:           m.mode.String(),
		Interface:      m.iface,
		PacketsPassed:  m.stats.passed.Load(),
		PacketsDropped: m.stats.dropped.Load(),
		BansActive:     activeBans,
		UptimeSeconds:  uptime,
	}
}

// StatsHandler returns an http.HandlerFunc that serves /api/ebpf/stats as JSON.
func (m *Manager) StatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := m.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snap); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}
}
