package db

import (
	"database/sql"
	"fmt"
	"log/slog"
)

// migration upgrades the schema by one version. Each runs in its own
// transaction and the version is stored in SQLite's PRAGMA user_version, so a
// crash mid-migration leaves the database at the previous version.
type migration struct {
	version int
	name    string
	up      func(tx *sql.Tx) error
}

var migrations = []migration{
	{1, "baseline schema", migrateBaseline},
	{2, "typed events table, capture details, indexes", migrateEventsV2},
	{3, "event kind/class/scanner/fingerprints, ip_intel", migrateIntelV3},
}

// migrate brings the database up to the latest schema version.
func migrate(db *sql.DB) error {
	var current int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		slog.Info("db: applying migration", "version", m.version, "name", m.name)
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := m.up(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		// PRAGMA does not accept bound parameters.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, m.version)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// migrateBaseline creates the original (pre-versioning) schema if absent and
// upgrades very old databases that predate the protocol column.
func migrateBaseline(tx *sql.Tx) error {
	if _, err := tx.Exec(`
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
	`); err != nil {
		return err
	}
	// Databases created before the protocol column existed lack it; the error
	// for "duplicate column" on current ones is expected and ignored.
	_, _ = tx.Exec(`ALTER TABLE events ADD COLUMN protocol TEXT NOT NULL DEFAULT 'tcp'`)
	return nil
}

// migrateEventsV2 rebuilds events with an INTEGER dst_port, adds the capture
// detail / enrichment columns and the indexes the history queries need.
func migrateEventsV2(tx *sql.Tx) error {
	_, err := tx.Exec(`
		CREATE TABLE events_v2 (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			time        TEXT    NOT NULL,
			src_ip      TEXT    NOT NULL,
			dst_ip      TEXT    NOT NULL,
			dst_port    INTEGER NOT NULL DEFAULT 0,
			protocol    TEXT    NOT NULL DEFAULT 'tcp',
			src_lat     REAL    NOT NULL DEFAULT 0,
			src_lon     REAL    NOT NULL DEFAULT 0,
			dst_lat     REAL    NOT NULL DEFAULT 0,
			dst_lon     REAL    NOT NULL DEFAULT 0,
			src_city    TEXT    NOT NULL DEFAULT '',
			dst_city    TEXT    NOT NULL DEFAULT '',
			src_cc      TEXT    NOT NULL DEFAULT '',
			dst_cc      TEXT    NOT NULL DEFAULT '',
			asn         INTEGER NOT NULL DEFAULT 0,
			asn_org     TEXT    NOT NULL DEFAULT '',
			client_data TEXT    NOT NULL DEFAULT '',
			detail      TEXT    NOT NULL DEFAULT '',
			tags        TEXT    NOT NULL DEFAULT '',
			meta        TEXT    NOT NULL DEFAULT ''
		);

		INSERT INTO events_v2
			(id, time, src_ip, dst_ip, dst_port, protocol,
			 src_lat, src_lon, dst_lat, dst_lon,
			 src_city, dst_city, src_cc, dst_cc)
		SELECT id, time, src_ip, dst_ip, CAST(dst_port AS INTEGER), protocol,
		       src_lat, src_lon, dst_lat, dst_lon,
		       src_city, dst_city, src_cc, dst_cc
		FROM events;

		DROP TABLE events;
		ALTER TABLE events_v2 RENAME TO events;

		CREATE INDEX events_time   ON events(time);
		CREATE INDEX events_src_ip ON events(src_ip, id);
		CREATE INDEX events_port   ON events(dst_port, id);
		CREATE INDEX events_cc     ON events(src_cc, id);
	`)
	return err
}

// migrateIntelV3 adds the classification columns (kind, class, scanner), the
// campaign fingerprints and the per-IP intelligence cache.
func migrateIntelV3(tx *sql.Tx) error {
	_, err := tx.Exec(`
		ALTER TABLE events ADD COLUMN kind    TEXT NOT NULL DEFAULT '';
		ALTER TABLE events ADD COLUMN class   TEXT NOT NULL DEFAULT '';
		ALTER TABLE events ADD COLUMN scanner TEXT NOT NULL DEFAULT '';
		ALTER TABLE events ADD COLUMN fp      TEXT NOT NULL DEFAULT '';

		CREATE INDEX events_kind ON events(kind, id);

		CREATE TABLE ip_intel (
			ip          TEXT PRIMARY KEY,
			rdns        TEXT NOT NULL DEFAULT '',
			scanner     TEXT NOT NULL DEFAULT '',
			greynoise   TEXT NOT NULL DEFAULT '',
			abuse_score INTEGER NOT NULL DEFAULT 0,
			updated     TEXT NOT NULL
		);
	`)
	return err
}
