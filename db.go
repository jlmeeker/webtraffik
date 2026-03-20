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
	db *sql.DB
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
	return &eventDB{db: db}, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			time     TEXT    NOT NULL,
			src_ip   TEXT    NOT NULL,
			dst_ip   TEXT    NOT NULL,
			dst_port TEXT    NOT NULL,
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
	return err
}

// insert persists a single ConnectionEvent. Errors are logged but not fatal —
// the app keeps running even if the DB write fails.
func (e *eventDB) insert(ev ConnectionEvent) {
	_, err := e.db.Exec(`
		INSERT INTO events
			(time, src_ip, dst_ip, dst_port,
			 src_lat, src_lon, dst_lat, dst_lon,
			 src_city, dst_city, src_cc, dst_cc)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Time, ev.SrcIP, ev.DstIP, ev.DstPort,
		ev.SrcLat, ev.SrcLon, ev.DstLat, ev.DstLon,
		ev.SrcCity, ev.DstCity, ev.SrcCC, ev.DstCC,
	)
	if err != nil {
		log.Printf("DB insert error: %v", err)
	}
}

// loadHistory returns the most recent `limit` events, oldest-first, ready to
// replay to a new WebSocket client.
func (e *eventDB) loadHistory(limit int) ([]ConnectionEvent, error) {
	rows, err := e.db.Query(`
		SELECT time, src_ip, dst_ip, dst_port,
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
			&ev.Time, &ev.SrcIP, &ev.DstIP, &ev.DstPort,
			&ev.SrcLat, &ev.SrcLon, &ev.DstLat, &ev.DstLon,
			&ev.SrcCity, &ev.DstCity, &ev.SrcCC, &ev.DstCC,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

// close releases the database connection.
func (e *eventDB) close() {
	if err := e.db.Close(); err != nil {
		log.Printf("DB close error: %v", err)
	}
}
