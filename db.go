package main

import (
	"database/sql"
	"log"
	"path/filepath"

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
	`)
	if err != nil {
		return err
	}
	// Migrate existing databases that predate the protocol column.
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'`)
	return nil
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

// close drains the insert queue and releases the database connection.
func (e *eventDB) close() {
	close(e.insertQ) // signal writeLoop to flush and exit
	<-e.done         // wait for writeLoop to finish
	if err := e.db.Close(); err != nil {
		log.Printf("DB close error: %v", err)
	}
}
