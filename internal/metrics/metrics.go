package metrics

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"webtraffik/internal/db"
	"webtraffik/internal/event"
)

// ── Metrics configuration ───────────────────────────────────────────────────
const (
	metricsFlushInterval = 5 * time.Second // how often dirty counters are flushed to SQLite
)

// metricKey identifies a single counter: (name, canonical label string, hour bucket).
type metricKey struct {
	name   string
	labels string // canonical sorted "cc=CN,port=22,protocol=tcp,service=SSH"
	bucket string // ISO hour: "2026-03-22T14:00:00Z"
}

// Cache holds in-memory counters that are periodically flushed to SQLite.
type Cache struct {
	mu       sync.Mutex
	counters map[metricKey]int64            // accumulated deltas since last flush
	ipSets   map[string]map[string]struct{} // bucket -> set of IPs (for unique_ips)
	dirty    bool

	db              *db.EventDB
	portServiceName func(string) string // injected to avoid import cycle
	done            chan struct{}
}

// NewCache creates the cache and starts the flush loop.
// portServiceName is a function to resolve port string → display name.
func NewCache(edb *db.EventDB, portServiceName func(string) string) *Cache {
	mc := &Cache{
		counters:        make(map[metricKey]int64),
		ipSets:          make(map[string]map[string]struct{}),
		db:              edb,
		portServiceName: portServiceName,
		done:            make(chan struct{}),
	}
	go mc.flushLoop()
	return mc
}

// currentBucket returns the current UTC hour truncated to the hour as an ISO string.
func currentBucket() string {
	return time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)
}

// Record records a connection event into the metrics cache.
// Called from handleCapture() — must be fast and non-blocking.
func (mc *Cache) Record(ev event.ConnectionEvent) {
	bucket := currentBucket()
	port := ev.DstPort
	protocol := ev.Protocol
	service := mc.portServiceName(port)
	cc := ev.SrcCC
	if cc == "" {
		cc = "XX" // unknown country
	}

	labels := db.CanonLabels(
		"cc="+cc,
		"port="+port,
		"protocol="+protocol,
		"service="+service,
	)

	mc.mu.Lock()
	mc.counters[metricKey{db.MetricConnections, labels, bucket}]++

	// Track unique IPs per bucket
	if mc.ipSets[bucket] == nil {
		mc.ipSets[bucket] = make(map[string]struct{})
	}
	mc.ipSets[bucket][ev.SrcIP] = struct{}{}

	mc.dirty = true
	mc.mu.Unlock()
}

// RecordBan records a ban event (type = "auto" or "manual").
func (mc *Cache) RecordBan(banType string) {
	bucket := currentBucket()
	labels := db.CanonLabels("type=" + banType)

	mc.mu.Lock()
	mc.counters[metricKey{db.MetricBans, labels, bucket}]++
	mc.dirty = true
	mc.mu.Unlock()
}

// flushLoop periodically writes dirty counters to SQLite.
func (mc *Cache) flushLoop() {
	defer close(mc.done)
	ticker := time.NewTicker(metricsFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		mc.flush()
	}
}

// flush snapshots and clears dirty counters, then upserts them into the DB.
func (mc *Cache) flush() {
	mc.mu.Lock()
	if !mc.dirty {
		mc.mu.Unlock()
		return
	}

	// Snapshot counters and clear
	snap := mc.counters
	mc.counters = make(map[metricKey]int64, len(snap))

	// Snapshot unique IP counts per bucket and clear old buckets.
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
	var batch []db.MetricsRow
	for key, delta := range snap {
		batch = append(batch, db.MetricsRow{
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
		batch = append(batch, db.MetricsRow{
			Name:   db.MetricUniqueIPs,
			Labels: "",
			Bucket: bucket,
			Delta:  count,
			AbsMax: true, // signal to use MAX instead of addition
		})
	}

	if len(batch) > 0 {
		if err := mc.db.UpsertMetrics(batch); err != nil {
			log.Printf("metrics: flush error: %v", err)
		}
	}
}

// Close stops the flush loop and performs a final flush.
func (mc *Cache) Close() {
	mc.flush() // final flush
}

// ── API types ───────────────────────────────────────────────────────────────

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
	TimeBuckets     []TimeBucket            `json:"time_buckets,omitempty"`
	PortTimeline    map[string][]TimeBucket `json:"port_timeline,omitempty"`
	CountryTimeline map[string][]TimeBucket `json:"country_timeline,omitempty"`
}

// TimeBucket is a single hour's aggregated counts.
type TimeBucket struct {
	Bucket    string `json:"bucket"`
	Value     int64  `json:"value"`
	UniqueIPs int64  `json:"unique_ips,omitempty"`
	Bans      int64  `json:"bans,omitempty"`
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
func (mc *Cache) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mq := db.MetricsQuery{
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

	rows, err := mc.db.QueryMetrics(mq)
	if err != nil {
		http.Error(w, "metrics query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Aggregate rows by (name, labels) summing values across buckets
	type aggKey struct{ name, labels string }
	agg := make(map[aggKey]int64)
	timeBuckets := make(map[string]int64)
	ipBuckets := make(map[string]int64)
	banBuckets := make(map[string]int64)
	portBuckets := make(map[string]map[string]int64)
	countryBuckets := make(map[string]map[string]int64)

	for _, row := range rows {
		agg[aggKey{row.Name, row.Labels}] += row.Value
		switch row.Name {
		case db.MetricConnections:
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
		case db.MetricUniqueIPs:
			ipBuckets[row.Bucket] += row.Value
		case db.MetricBans:
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
		case db.MetricConnections:
			resp.Connections = append(resp.Connections, series)
		case db.MetricBans:
			resp.Bans = append(resp.Bans, series)
		case db.MetricUniqueIPs:
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
func (mc *Cache) HandleMetricsPrometheus(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mq := db.MetricsQuery{
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

	rows, err := mc.db.QueryMetrics(mq)
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
		if name == db.MetricUniqueIPs {
			metricType = "gauge"
		}
		fmt.Fprintf(w, "# HELP %s webTraffik metric\n", promName)
		fmt.Fprintf(w, "# TYPE %s %s\n", promName, metricType)
		for _, e := range entries {
			if e.labels == "" {
				fmt.Fprintf(w, "%s %d\n", promName, e.value)
			} else {
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
