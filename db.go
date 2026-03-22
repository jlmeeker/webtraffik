package main

import (
	"database/sql"
	"log"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const eventsDBFilename = "events.db"

// eventDB wraps the SQLite connection used for event persistence.
type eventDB struct {
	db      *sql.DB
	insertQ chan ConnectionEvent // async insert queue
	done    chan struct{}        // closed when writer goroutine exits
}

// openEventDB opens (or creates) the SQLite database at dir/events.db,
// creates the events table if it doesn't exist, and enables WAL mode for
// better write concurrency.
func openEventDB(dir string) (*eventDB, error) {
	path := filepath.Join(dir, eventsDBFilename)
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
	// hard crash (power loss).  Normal OS/app crashes are safe with WAL.
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, err
	}

	if err := createSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("Event DB opened: %s", path)
	edb := &eventDB{
		db:      db,
		insertQ: make(chan ConnectionEvent, 4096),
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
	`)
	if err != nil {
		return err
	}
	// Migrate existing databases that predate the protocol column.
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'`)
	return nil
}

// persistBan inserts or replaces a BanEntry in the banned_ips table.
func (e *eventDB) persistBan(b *BanEntry) error {
	_, err := e.db.Exec(`
		INSERT OR REPLACE INTO banned_ips (ip, port, service, banned_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		b.IP, b.Port, b.Service,
		b.BannedAt.UTC().Format(time.RFC3339),
		b.ExpiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

// expireBan removes a ban record from the database once the cooldown has elapsed.
func (e *eventDB) expireBan(ip, port string) error {
	_, err := e.db.Exec(`DELETE FROM banned_ips WHERE ip = ? AND port = ?`, ip, port)
	return err
}

// loadActiveBans returns all ban records whose expires_at is in the future.
func (e *eventDB) loadActiveBans() ([]BanEntry, error) {
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

	var bans []BanEntry
	for rows.Next() {
		var b BanEntry
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

// insert queues a ConnectionEvent for async persistence. If the queue is full
// the event is dropped (logged) — capture is never blocked on DB writes.
func (e *eventDB) insert(ev ConnectionEvent) {
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
func (e *eventDB) writeLoop() {
	defer close(e.done)

	const batchMax = 64
	batch := make([]ConnectionEvent, 0, batchMax)

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
func (e *eventDB) flushBatch(batch []ConnectionEvent) {
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

// loadHistory returns the most recent `limit` events, oldest-first, ready to
// replay to a new WebSocket client.
func (e *eventDB) loadHistory(limit int) ([]ConnectionEvent, error) {
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

	var events []ConnectionEvent
	for rows.Next() {
		var ev ConnectionEvent
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

// loadHistorySince returns all events since the given RFC3339 timestamp,
// oldest-first, with no row limit.
func (e *eventDB) loadHistorySince(since string) ([]ConnectionEvent, error) {
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

	var events []ConnectionEvent
	for rows.Next() {
		var ev ConnectionEvent
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

// HistoryFilter holds optional filter criteria for queryHistory.
// Zero values / empty strings mean "no filter" for that field.
type HistoryFilter struct {
	Country  string // src_cc (2-letter code, case-insensitive)
	IP       string // src_ip prefix/exact match
	Port     string // dst_port exact match
	Service  string // resolved via portServiceName(); matched against dst_port
	DateFrom string // RFC3339 / YYYY-MM-DD lower bound (inclusive)
	DateTo   string // RFC3339 / YYYY-MM-DD upper bound (inclusive, treated as end-of-day)
}

// queryHistory executes a filtered SELECT against the events table and returns
// matching events oldest-first.
func (e *eventDB) queryHistory(f HistoryFilter) ([]ConnectionEvent, error) {
	where := []string{}
	args := []interface{}{}

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
	if f.Service != "" {
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
			return []ConnectionEvent{}, nil
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

	var events []ConnectionEvent
	for rows.Next() {
		var ev ConnectionEvent
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

// close drains the insert queue and releases the database connection.
func (e *eventDB) close() {
	close(e.insertQ) // signal writeLoop to flush and exit
	<-e.done         // wait for writeLoop to finish
	if err := e.db.Close(); err != nil {
		log.Printf("DB close error: %v", err)
	}
}
