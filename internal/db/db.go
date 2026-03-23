package db

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"webtraffik/internal/event"

	_ "modernc.org/sqlite"
)

const EventsDBFilename = "events.db"

// ── Metric name constants (shared with metrics package) ─────────────────────

const (
	MetricConnections = "connections" // labels: port, protocol, service, cc
	MetricBans        = "bans"        // labels: type (auto/manual)
	MetricUniqueIPs   = "unique_ips"  // no labels, per-hour unique IP count
)

// ── eventDB ──────────────────────────────────────────────────────────────────

// EventDB wraps the SQLite connection used for event persistence.
type EventDB struct {
	db      *sql.DB
	insertQ chan event.ConnectionEvent // async insert queue
	done    chan struct{}              // closed when writer goroutine exits
}

// OpenEventDB opens (or creates) the SQLite database at dir/events.db,
// creates the events table if it doesn't exist, and enables WAL mode for
// better write concurrency.
func OpenEventDB(dir string) (*EventDB, error) {
	path := filepath.Join(dir, EventsDBFilename)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Single writer is fine; WAL lets readers not block the writer.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, err
	}

	// Keep writes fast; we can afford to lose the last second of events on a
	// hard crash (power loss). Normal OS/app crashes are safe with WAL.
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, err
	}

	if err := createSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("Event DB opened: %s", path)
	edb := &EventDB{
		db:      db,
		insertQ: make(chan event.ConnectionEvent, 4096),
		done:    make(chan struct{}),
	}
	go edb.writeLoop()
	return edb, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			time     TEXT    NOT NULL,
			src_ip   TEXT    NOT NULL,
			dst_ip   TEXT    NOT NULL,
			dst_port TEXT    NOT NULL,
			protocol TEXT    NOT NULL DEFAULT 'tcp',
			src_lat  REAL    NOT NULL DEFAULT 0,
			src_lon  REAL    NOT NULL DEFAULT 0,
			dst_lat  REAL    NOT NULL DEFAULT 0,
			dst_lon  REAL    NOT NULL DEFAULT 0,
			src_city TEXT    NOT NULL DEFAULT '',
			dst_city TEXT    NOT NULL DEFAULT '',
			src_cc   TEXT    NOT NULL DEFAULT '',
			dst_cc   TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS events_id_desc ON events(id DESC);

		CREATE TABLE IF NOT EXISTS banned_ips (
			ip         TEXT NOT NULL,
			port       TEXT NOT NULL,
			service    TEXT NOT NULL DEFAULT '',
			banned_at  TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			PRIMARY KEY (ip, port)
		);

		CREATE TABLE IF NOT EXISTS metrics (
			name   TEXT NOT NULL,
			labels TEXT NOT NULL DEFAULT '',
			bucket TEXT NOT NULL,
			value  REAL NOT NULL DEFAULT 0,
			PRIMARY KEY (name, labels, bucket)
		);
		CREATE INDEX IF NOT EXISTS idx_metrics_bucket ON metrics(bucket);
	`)
	if err != nil {
		return err
	}
	// Migrate existing databases that predate the protocol column.
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'`)
	return nil
}

// PersistBan inserts or replaces a BanEntry in the banned_ips table.
func (e *EventDB) PersistBan(ip, port, service string, bannedAt, expiresAt time.Time) error {
	_, err := e.db.Exec(`
		INSERT OR REPLACE INTO banned_ips (ip, port, service, banned_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		ip, port, service,
		bannedAt.UTC().Format(time.RFC3339),
		expiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

// ExpireBan removes a ban record from the database once the cooldown has elapsed.
func (e *EventDB) ExpireBan(ip, port string) error {
	_, err := e.db.Exec(`DELETE FROM banned_ips WHERE ip = ? AND port = ?`, ip, port)
	return err
}

// BanRecord holds a persisted ban row returned from LoadActiveBans.
type BanRecord struct {
	IP        string
	Port      string
	Service   string
	BannedAt  time.Time
	ExpiresAt time.Time
}

// LoadActiveBans returns all ban records whose expires_at is in the future.
func (e *EventDB) LoadActiveBans() ([]BanRecord, error) {
	rows, err := e.db.Query(`
		SELECT ip, port, service, banned_at, expires_at
		FROM banned_ips
		WHERE expires_at > ?`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []BanRecord
	for rows.Next() {
		var b BanRecord
		var bannedAt, expiresAt string
		if err := rows.Scan(&b.IP, &b.Port, &b.Service, &bannedAt, &expiresAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, bannedAt); err == nil {
			b.BannedAt = t
		}
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			b.ExpiresAt = t
		}
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// Insert queues a ConnectionEvent for async persistence. If the queue is full
// the event is dropped (logged) — capture is never blocked on DB writes.
func (e *EventDB) Insert(ev event.ConnectionEvent) {
	select {
	case e.insertQ <- ev:
	default:
		log.Printf("DB insert queue full, dropping event from %s", ev.SrcIP)
	}
}

// writeLoop is the dedicated goroutine that drains the insert queue and
// batches writes into SQLite. It groups pending events into a single
// transaction for throughput, flushing whenever the queue drains or a
// batch reaches 64 events.
func (e *EventDB) writeLoop() {
	defer close(e.done)

	const batchMax = 64
	batch := make([]event.ConnectionEvent, 0, batchMax)

	for {
		// Block until at least one event is available (or channel closed).
		ev, ok := <-e.insertQ
		if !ok {
			// Channel closed — flush remaining and exit.
			e.flushBatch(batch)
			return
		}
		batch = append(batch, ev)

		// Drain any additional queued events up to batchMax.
	drain:
		for len(batch) < batchMax {
			select {
			case ev, ok := <-e.insertQ:
				if !ok {
					e.flushBatch(batch)
					return
				}
				batch = append(batch, ev)
			default:
				break drain
			}
		}

		e.flushBatch(batch)
		batch = batch[:0]
	}
}

// flushBatch writes a slice of events to SQLite in a single transaction.
func (e *EventDB) flushBatch(batch []event.ConnectionEvent) {
	if len(batch) == 0 {
		return
	}

	tx, err := e.db.Begin()
	if err != nil {
		log.Printf("DB begin tx error: %v", err)
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO events
			(time, src_ip, dst_ip, dst_port, protocol,
			 src_lat, src_lon, dst_lat, dst_lon,
			 src_city, dst_city, src_cc, dst_cc)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		log.Printf("DB prepare error: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, ev := range batch {
		_, err := stmt.Exec(
			ev.Time, ev.SrcIP, ev.DstIP, ev.DstPort, ev.Protocol,
			ev.SrcLat, ev.SrcLon, ev.DstLat, ev.DstLon,
			ev.SrcCity, ev.DstCity, ev.SrcCC, ev.DstCC,
		)
		if err != nil {
			log.Printf("DB insert error: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("DB commit error: %v", err)
	}
}

// LoadHistory returns the most recent `limit` events, oldest-first, ready to
// replay to a new WebSocket client.
func (e *EventDB) LoadHistory(limit int) ([]event.ConnectionEvent, error) {
	rows, err := e.db.Query(`
		SELECT time, src_ip, dst_ip, dst_port, protocol,
		       src_lat, src_lon, dst_lat, dst_lon,
		       src_city, dst_city, src_cc, dst_cc
		FROM (
			SELECT * FROM events ORDER BY id DESC LIMIT ?
		) ORDER BY id ASC`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []event.ConnectionEvent
	for rows.Next() {
		var ev event.ConnectionEvent
		if err := rows.Scan(
			&ev.Time, &ev.SrcIP, &ev.DstIP, &ev.DstPort, &ev.Protocol,
			&ev.SrcLat, &ev.SrcLon, &ev.DstLat, &ev.DstLon,
			&ev.SrcCity, &ev.DstCity, &ev.SrcCC, &ev.DstCC,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// LoadHistorySince returns all events since the given RFC3339 timestamp,
// oldest-first, with no row limit.
func (e *EventDB) LoadHistorySince(since string) ([]event.ConnectionEvent, error) {
	rows, err := e.db.Query(`
		SELECT time, src_ip, dst_ip, dst_port, protocol,
		       src_lat, src_lon, dst_lat, dst_lon,
		       src_city, dst_city, src_cc, dst_cc
		FROM events
		WHERE time >= ?
		ORDER BY id ASC`,
		since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []event.ConnectionEvent
	for rows.Next() {
		var ev event.ConnectionEvent
		if err := rows.Scan(
			&ev.Time, &ev.SrcIP, &ev.DstIP, &ev.DstPort, &ev.Protocol,
			&ev.SrcLat, &ev.SrcLon, &ev.DstLat, &ev.DstLon,
			&ev.SrcCity, &ev.DstCity, &ev.SrcCC, &ev.DstCC,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// HistoryFilter holds optional filter criteria for QueryHistory.
// Zero values / empty strings mean "no filter" for that field.
type HistoryFilter struct {
	Country  string // src_cc (2-letter code, case-insensitive)
	IP       string // src_ip prefix/exact match
	Port     string // dst_port exact match
	Service  string // resolved via portServiceNameFn; matched against dst_port
	DateFrom string // RFC3339 / YYYY-MM-DD lower bound (inclusive)
	DateTo   string // RFC3339 / YYYY-MM-DD upper bound (inclusive, treated as end-of-day)
}

// QueryHistory executes a filtered SELECT against the events table and returns
// matching events oldest-first.
// portForService is a callback to resolve a service name to matching port strings.
func (e *EventDB) QueryHistory(f HistoryFilter, portsForService func(string) []string) ([]event.ConnectionEvent, error) {
	var where []string
	var args []interface{}

	if f.Country != "" {
		where = append(where, "UPPER(src_cc) = UPPER(?)")
		args = append(args, f.Country)
	}
	if f.IP != "" {
		where = append(where, "src_ip LIKE ?")
		args = append(args, f.IP+"%")
	}
	if f.Port != "" {
		where = append(where, "dst_port = ?")
		args = append(args, f.Port)
	}
	// Service filter: resolve port numbers that share the given service name
	if f.Service != "" && portsForService != nil {
		ports := portsForService(f.Service)
		if len(ports) > 0 {
			placeholders := ""
			for i, p := range ports {
				if i > 0 {
					placeholders += ","
				}
				placeholders += "?"
				args = append(args, p)
			}
			where = append(where, "dst_port IN ("+placeholders+")")
		} else {
			// No ports match → return empty result set
			return []event.ConnectionEvent{}, nil
		}
	}
	if f.DateFrom != "" {
		where = append(where, "time >= ?")
		args = append(args, f.DateFrom)
	}
	if f.DateTo != "" {
		// Treat DateTo as end-of-day if only a date (no time component) is given
		dateTo := f.DateTo
		if len(dateTo) == 10 {
			dateTo += "T23:59:59Z"
		}
		where = append(where, "time <= ?")
		args = append(args, dateTo)
	}

	// Build the query with optional WHERE filters, ordered oldest-first.
	query := `SELECT time, src_ip, dst_ip, dst_port, protocol,
	                 src_lat, src_lon, dst_lat, dst_lon,
	                 src_city, dst_city, src_cc, dst_cc
	          FROM events`
	if len(where) > 0 {
		query += " WHERE "
		for i, w := range where {
			if i > 0 {
				query += " AND "
			}
			query += w
		}
	}
	query += " ORDER BY id ASC"

	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []event.ConnectionEvent
	for rows.Next() {
		var ev event.ConnectionEvent
		if err := rows.Scan(
			&ev.Time, &ev.SrcIP, &ev.DstIP, &ev.DstPort, &ev.Protocol,
			&ev.SrcLat, &ev.SrcLon, &ev.DstLat, &ev.DstLon,
			&ev.SrcCity, &ev.DstCity, &ev.SrcCC, &ev.DstCC,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// Close drains the insert queue and releases the database connection.
func (e *EventDB) Close() {
	close(e.insertQ) // signal writeLoop to flush and exit
	<-e.done         // wait for writeLoop to finish
	if err := e.db.Close(); err != nil {
		log.Printf("DB close error: %v", err)
	}
}

// ── Metrics persistence ─────────────────────────────────────────────────────

// MetricsRow is a single row to upsert into the metrics table.
type MetricsRow struct {
	Name   string
	Labels string
	Bucket string
	Delta  int64 // added to existing value (for counters)
	Value  int64 // used by QueryMetrics results
	AbsMax bool  // if true, use MAX(value, ?) instead of value + ?
}

// MetricsQuery holds the optional time range for /api/metrics.
type MetricsQuery struct {
	From string // ISO8601 lower bound (inclusive), truncated to hour
	To   string // ISO8601 upper bound (inclusive), truncated to hour
}

// UpsertMetrics writes a batch of metric deltas to SQLite in a single transaction.
// For normal counters it adds the delta to the existing value.
// For AbsMax rows (unique_ips) it sets value = MAX(existing, new).
func (e *EventDB) UpsertMetrics(batch []MetricsRow) error {
	tx, err := e.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmtAdd, err := tx.Prepare(`
		INSERT INTO metrics (name, labels, bucket, value)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name, labels, bucket) DO UPDATE SET value = value + excluded.value`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare add stmt: %w", err)
	}
	defer stmtAdd.Close()

	stmtMax, err := tx.Prepare(`
		INSERT INTO metrics (name, labels, bucket, value)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name, labels, bucket) DO UPDATE SET value = MAX(value, excluded.value)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare max stmt: %w", err)
	}
	defer stmtMax.Close()

	for _, row := range batch {
		if row.AbsMax {
			if _, err := stmtMax.Exec(row.Name, row.Labels, row.Bucket, row.Delta); err != nil {
				log.Printf("metrics upsert (max) error: %v", err)
			}
		} else {
			if _, err := stmtAdd.Exec(row.Name, row.Labels, row.Bucket, row.Delta); err != nil {
				log.Printf("metrics upsert (add) error: %v", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// QueryMetrics returns raw metric rows, optionally filtered by time range.
func (e *EventDB) QueryMetrics(mq MetricsQuery) ([]MetricsRow, error) {
	var where []string
	var args []interface{}

	if mq.From != "" {
		where = append(where, "bucket >= ?")
		args = append(args, mq.From)
	}
	if mq.To != "" {
		where = append(where, "bucket < ?")
		args = append(args, mq.To)
	}

	query := `SELECT name, labels, bucket, value FROM metrics`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY bucket ASC"

	rows, err := e.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MetricsRow
	for rows.Next() {
		var r MetricsRow
		if err := rows.Scan(&r.Name, &r.Labels, &r.Bucket, &r.Value); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// CanonLabels builds a canonical, sorted label string from key=value pairs.
func CanonLabels(pairs ...string) string {
	if len(pairs) == 0 {
		return ""
	}
	sorted := make([]string, len(pairs))
	copy(sorted, pairs)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// BackfillMetrics generates metric rows from existing events data.
// It aggregates events into hourly buckets for connections (by port/protocol/cc)
// and unique IPs. This is idempotent — it only inserts if the metrics table is empty.
// portServiceName is a callback to resolve a port string to a service name.
func (e *EventDB) BackfillMetrics(portServiceName func(string) string) error {
	// Check if metrics already have data
	var count int
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM metrics`).Scan(&count); err != nil {
		return fmt.Errorf("check metrics count: %w", err)
	}
	if count > 0 {
		log.Printf("Metrics table has %d rows, skipping backfill", count)
		return nil
	}

	log.Println("Backfilling metrics from events table...")
	start := time.Now()

	// 1. Backfill connections: GROUP BY hour bucket, port, protocol, country code
	connRows, err := e.db.Query(`
		SELECT
			strftime('%Y-%m-%dT%H:00:00Z', time) AS bucket,
			dst_port,
			protocol,
			CASE WHEN src_cc = '' THEN 'XX' ELSE src_cc END AS cc,
			COUNT(*) AS cnt
		FROM events
		GROUP BY bucket, dst_port, protocol, cc`)
	if err != nil {
		return fmt.Errorf("backfill connections query: %w", err)
	}

	var batch []MetricsRow
	for connRows.Next() {
		var bucket, port, protocol, cc string
		var cnt int64
		if err := connRows.Scan(&bucket, &port, &protocol, &cc, &cnt); err != nil {
			connRows.Close()
			return fmt.Errorf("backfill connections scan: %w", err)
		}
		service := portServiceName(port)
		labels := CanonLabels(
			"cc="+cc,
			"port="+port,
			"protocol="+protocol,
			"service="+service,
		)
		batch = append(batch, MetricsRow{
			Name:   MetricConnections,
			Labels: labels,
			Bucket: bucket,
			Delta:  cnt,
		})
	}
	connRows.Close()

	// 2. Backfill unique IPs per hour bucket
	ipRows, err := e.db.Query(`
		SELECT
			strftime('%Y-%m-%dT%H:00:00Z', time) AS bucket,
			COUNT(DISTINCT src_ip) AS uniq
		FROM events
		GROUP BY bucket`)
	if err != nil {
		return fmt.Errorf("backfill unique_ips query: %w", err)
	}

	for ipRows.Next() {
		var bucket string
		var uniq int64
		if err := ipRows.Scan(&bucket, &uniq); err != nil {
			ipRows.Close()
			return fmt.Errorf("backfill unique_ips scan: %w", err)
		}
		batch = append(batch, MetricsRow{
			Name:   MetricUniqueIPs,
			Labels: "",
			Bucket: bucket,
			Delta:  uniq,
			AbsMax: true,
		})
	}
	ipRows.Close()

	if len(batch) == 0 {
		log.Println("No events to backfill metrics from")
		return nil
	}

	// Sort batch for deterministic insert order
	sort.Slice(batch, func(i, j int) bool {
		if batch[i].Bucket != batch[j].Bucket {
			return batch[i].Bucket < batch[j].Bucket
		}
		if batch[i].Name != batch[j].Name {
			return batch[i].Name < batch[j].Name
		}
		return batch[i].Labels < batch[j].Labels
	})

	if err := e.UpsertMetrics(batch); err != nil {
		return fmt.Errorf("backfill upsert: %w", err)
	}

	log.Printf("Backfilled %d metric rows from events in %v", len(batch), time.Since(start).Round(time.Millisecond))
	return nil
}
