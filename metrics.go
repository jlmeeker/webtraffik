package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Metrics configuration ───────────────────────────────────────────────────
const (
	metricsFlushInterval = 5 * time.Second // how often dirty counters are flushed to SQLite
)

// ── Metric names ────────────────────────────────────────────────────────────
const (
	metricConnections = "connections" // labels: port, protocol, service, cc
	metricBans        = "bans"        // labels: type (auto/manual)
	metricUniqueIPs   = "unique_ips"  // no labels, per-hour unique IP count
)

// metricKey identifies a single counter: (name, canonical label string, hour bucket).
type metricKey struct {
	name   string
	labels string // canonical sorted "cc=CN,port=22,protocol=tcp,service=SSH"
	bucket string // ISO hour: "2026-03-22T14:00:00Z"
}

// metricsCache holds in-memory counters that are periodically flushed to SQLite.
type metricsCache struct {
	mu       sync.Mutex
	counters map[metricKey]int64            // accumulated deltas since last flush
	ipSets   map[string]map[string]struct{} // bucket -> set of IPs (for unique_ips)
	dirty    bool

	db   *eventDB
	done chan struct{}
}

var appMetrics *metricsCache

// newMetricsCache creates the cache and starts the flush loop.
func newMetricsCache(db *eventDB) *metricsCache {
	mc := &metricsCache{
		counters: make(map[metricKey]int64),
		ipSets:   make(map[string]map[string]struct{}),
		db:       db,
		done:     make(chan struct{}),
	}
	go mc.flushLoop()
	return mc
}

// currentBucket returns the current UTC hour truncated to the hour as an ISO string.
func currentBucket() string {
	return time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)
}

// canonLabels builds a canonical, sorted label string from key=value pairs.
func canonLabels(pairs ...string) string {
	if len(pairs) == 0 {
		return ""
	}
	// pairs are already key=value strings; sort them for canonical order
	sorted := make([]string, len(pairs))
	copy(sorted, pairs)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// Record records a connection event into the metrics cache.
// Called from handleCapture() — must be fast and non-blocking.
func (mc *metricsCache) Record(ev ConnectionEvent) {
	bucket := currentBucket()
	port := ev.DstPort
	protocol := ev.Protocol
	service := portServiceName(port)
	cc := ev.SrcCC
	if cc == "" {
		cc = "XX" // unknown country
	}

	labels := canonLabels(
		"cc="+cc,
		"port="+port,
		"protocol="+protocol,
		"service="+service,
	)

	mc.mu.Lock()
	mc.counters[metricKey{metricConnections, labels, bucket}]++

	// Track unique IPs per bucket
	if mc.ipSets[bucket] == nil {
		mc.ipSets[bucket] = make(map[string]struct{})
	}
	mc.ipSets[bucket][ev.SrcIP] = struct{}{}

	mc.dirty = true
	mc.mu.Unlock()
}

// RecordBan records a ban event (type = "auto" or "manual").
func (mc *metricsCache) RecordBan(banType string) {
	bucket := currentBucket()
	labels := canonLabels("type=" + banType)

	mc.mu.Lock()
	mc.counters[metricKey{metricBans, labels, bucket}]++
	mc.dirty = true
	mc.mu.Unlock()
}

// flushLoop periodically writes dirty counters to SQLite.
func (mc *metricsCache) flushLoop() {
	defer close(mc.done)
	ticker := time.NewTicker(metricsFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		mc.flush()
	}
}

// flush snapshots and clears dirty counters, then upserts them into the DB.
func (mc *metricsCache) flush() {
	mc.mu.Lock()
	if !mc.dirty {
		mc.mu.Unlock()
		return
	}

	// Snapshot counters and clear
	snap := mc.counters
	mc.counters = make(map[metricKey]int64, len(snap))

	// Snapshot unique IP counts per bucket and clear old buckets.
	// We keep the current bucket's IP set alive (it's still accumulating)
	// and flush counts for all buckets.
	cur := currentBucket()
	ipCounts := make(map[string]int64) // bucket -> unique IP count
	for bucket, ips := range mc.ipSets {
		ipCounts[bucket] = int64(len(ips))
		if bucket != cur {
			delete(mc.ipSets, bucket) // old hour, no longer accumulating
		}
	}

	mc.dirty = false
	mc.mu.Unlock()

	// Build the batch for DB upsert
	var batch []metricsRow
	for key, delta := range snap {
		batch = append(batch, metricsRow{
			Name:   key.name,
			Labels: key.labels,
			Bucket: key.bucket,
			Delta:  delta,
		})
	}

	// Unique IPs are stored as absolute values per bucket (not deltas),
	// because the count can only grow within an hour. We use a special
	// upsert that sets value = MAX(value, ?) instead of value = value + ?.
	for bucket, count := range ipCounts {
		batch = append(batch, metricsRow{
			Name:   metricUniqueIPs,
			Labels: "",
			Bucket: bucket,
			Delta:  count,
			AbsMax: true, // signal to use MAX instead of addition
		})
	}

	if len(batch) > 0 {
		if err := mc.db.upsertMetrics(batch); err != nil {
			log.Printf("metrics: flush error: %v", err)
		}
	}
}

// close stops the flush loop and performs a final flush.
func (mc *metricsCache) close() {
	mc.flush() // final flush
}

// ── API types ───────────────────────────────────────────────────────────────

// MetricsQuery holds the optional time range for /api/metrics.
type MetricsQuery struct {
	From string // ISO8601 lower bound (inclusive), truncated to hour
	To   string // ISO8601 upper bound (inclusive), truncated to hour
}

// MetricSeries is one metric name with all its label/value pairs.
type MetricSeries struct {
	Labels map[string]string `json:"labels"`
	Value  int64             `json:"value"`
}

// MetricsResponse is the JSON shape returned by /api/metrics.
type MetricsResponse struct {
	Connections     []MetricSeries          `json:"connections"`
	Bans            []MetricSeries          `json:"bans"`
	UniqueIPs       int64                   `json:"unique_ips"`
	TimeBuckets     []TimeBucket            `json:"time_buckets,omitempty"`     // hourly connection totals for timeline
	PortTimeline    map[string][]TimeBucket `json:"port_timeline,omitempty"`    // port -> hourly buckets
	CountryTimeline map[string][]TimeBucket `json:"country_timeline,omitempty"` // cc -> hourly buckets
}

// TimeBucket is a single hour's aggregated counts.
type TimeBucket struct {
	Bucket    string `json:"bucket"`
	Value     int64  `json:"value"`                // connections
	UniqueIPs int64  `json:"unique_ips,omitempty"` // unique source IPs this hour
	Bans      int64  `json:"bans,omitempty"`       // total bans this hour
}

// parseLabels converts "cc=CN,port=22,protocol=tcp,service=SSH" into a map.
func parseLabels(s string) map[string]string {
	if s == "" {
		return map[string]string{}
	}
	m := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

// HandleMetrics serves GET /api/metrics?from=...&to=...
func HandleMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mq := MetricsQuery{
		From: q.Get("from"),
		To:   q.Get("to"),
	}

	// Truncate to hour boundaries for clean bucket matching
	if mq.From != "" {
		if t, err := time.Parse(time.RFC3339, mq.From); err == nil {
			mq.From = t.UTC().Truncate(time.Hour).Format(time.RFC3339)
		}
	}
	if mq.To != "" {
		if t, err := time.Parse(time.RFC3339, mq.To); err == nil {
			// Include the full hour containing the "to" time
			mq.To = t.UTC().Truncate(time.Hour).Add(time.Hour).Format(time.RFC3339)
		}
	}

	rows, err := appMetrics.db.queryMetrics(mq)
	if err != nil {
		http.Error(w, "metrics query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate rows by (name, labels) summing values across buckets
	type aggKey struct{ name, labels string }
	agg := make(map[aggKey]int64)
	timeBuckets := make(map[string]int64)               // bucket -> total connections
	ipBuckets := make(map[string]int64)                 // bucket -> unique IPs
	banBuckets := make(map[string]int64)                // bucket -> total bans
	portBuckets := make(map[string]map[string]int64)    // port -> bucket -> count
	countryBuckets := make(map[string]map[string]int64) // cc -> bucket -> count

	for _, row := range rows {
		agg[aggKey{row.Name, row.Labels}] += row.Value
		switch row.Name {
		case metricConnections:
			timeBuckets[row.Bucket] += row.Value

			lbls := parseLabels(row.Labels)
			if p := lbls["port"]; p != "" {
				if portBuckets[p] == nil {
					portBuckets[p] = make(map[string]int64)
				}
				portBuckets[p][row.Bucket] += row.Value
			}
			if cc := lbls["cc"]; cc != "" {
				if countryBuckets[cc] == nil {
					countryBuckets[cc] = make(map[string]int64)
				}
				countryBuckets[cc][row.Bucket] += row.Value
			}
		case metricUniqueIPs:
			ipBuckets[row.Bucket] += row.Value
		case metricBans:
			banBuckets[row.Bucket] += row.Value
		}
	}

	resp := MetricsResponse{}

	for key, val := range agg {
		series := MetricSeries{
			Labels: parseLabels(key.labels),
			Value:  val,
		}
		switch key.name {
		case metricConnections:
			resp.Connections = append(resp.Connections, series)
		case metricBans:
			resp.Bans = append(resp.Bans, series)
		case metricUniqueIPs:
			// Sum across hour buckets — this is an approximation (overcounts)
			// but is the best we can do without raw event data
			resp.UniqueIPs += val
		}
	}

	// Sort connections by value descending for convenience
	sort.Slice(resp.Connections, func(i, j int) bool {
		return resp.Connections[i].Value > resp.Connections[j].Value
	})
	sort.Slice(resp.Bans, func(i, j int) bool {
		return resp.Bans[i].Value > resp.Bans[j].Value
	})

	// Build sorted time buckets for timeline chart.
	// Collect all bucket keys from connections, unique IPs, and bans.
	allBuckets := make(map[string]struct{})
	for b := range timeBuckets {
		allBuckets[b] = struct{}{}
	}
	for b := range ipBuckets {
		allBuckets[b] = struct{}{}
	}
	for b := range banBuckets {
		allBuckets[b] = struct{}{}
	}
	for bucket := range allBuckets {
		resp.TimeBuckets = append(resp.TimeBuckets, TimeBucket{
			Bucket:    bucket,
			Value:     timeBuckets[bucket],
			UniqueIPs: ipBuckets[bucket],
			Bans:      banBuckets[bucket],
		})
	}
	sort.Slice(resp.TimeBuckets, func(i, j int) bool {
		return resp.TimeBuckets[i].Bucket < resp.TimeBuckets[j].Bucket
	})

	// Build per-port timeline
	resp.PortTimeline = make(map[string][]TimeBucket, len(portBuckets))
	for port, buckets := range portBuckets {
		for b, v := range buckets {
			resp.PortTimeline[port] = append(resp.PortTimeline[port], TimeBucket{Bucket: b, Value: v})
		}
		sort.Slice(resp.PortTimeline[port], func(i, j int) bool {
			return resp.PortTimeline[port][i].Bucket < resp.PortTimeline[port][j].Bucket
		})
	}

	// Build per-country timeline
	resp.CountryTimeline = make(map[string][]TimeBucket, len(countryBuckets))
	for cc, buckets := range countryBuckets {
		for b, v := range buckets {
			resp.CountryTimeline[cc] = append(resp.CountryTimeline[cc], TimeBucket{Bucket: b, Value: v})
		}
		sort.Slice(resp.CountryTimeline[cc], func(i, j int) bool {
			return resp.CountryTimeline[cc][i].Bucket < resp.CountryTimeline[cc][j].Bucket
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleMetricsPrometheus serves GET /metrics in Prometheus exposition format.
func HandleMetricsPrometheus(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mq := MetricsQuery{
		From: q.Get("from"),
		To:   q.Get("to"),
	}

	if mq.From != "" {
		if t, err := time.Parse(time.RFC3339, mq.From); err == nil {
			mq.From = t.UTC().Truncate(time.Hour).Format(time.RFC3339)
		}
	}
	if mq.To != "" {
		if t, err := time.Parse(time.RFC3339, mq.To); err == nil {
			mq.To = t.UTC().Truncate(time.Hour).Add(time.Hour).Format(time.RFC3339)
		}
	}

	rows, err := appMetrics.db.queryMetrics(mq)
	if err != nil {
		http.Error(w, "metrics query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate by (name, labels)
	type aggKey struct{ name, labels string }
	agg := make(map[aggKey]int64)
	for _, row := range rows {
		agg[aggKey{row.Name, row.Labels}] += row.Value
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Group by metric name
	byName := make(map[string][]struct {
		labels string
		value  int64
	})
	for key, val := range agg {
		byName[key.name] = append(byName[key.name], struct {
			labels string
			value  int64
		}{key.labels, val})
	}

	// Write each metric
	for name, entries := range byName {
		promName := "webtraffik_" + name
		metricType := "counter"
		if name == metricUniqueIPs {
			metricType = "gauge"
		}
		fmt.Fprintf(w, "# HELP %s webTraffik metric\n", promName)
		fmt.Fprintf(w, "# TYPE %s %s\n", promName, metricType)
		for _, e := range entries {
			if e.labels == "" {
				fmt.Fprintf(w, "%s %d\n", promName, e.value)
			} else {
				// Convert "cc=CN,port=22" to {cc="CN",port="22"}
				promLabels := labelsToPrometheus(e.labels)
				fmt.Fprintf(w, "%s{%s} %d\n", promName, promLabels, e.value)
			}
		}
	}
}

// labelsToPrometheus converts "cc=CN,port=22" to `cc="CN",port="22"`.
func labelsToPrometheus(labels string) string {
	pairs := strings.Split(labels, ",")
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, kv[0], kv[1]))
		}
	}
	return strings.Join(parts, ",")
}
