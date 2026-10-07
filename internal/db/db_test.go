package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"webtraffik/internal/event"

	_ "modernc.org/sqlite"
)

func ev(ts time.Time, ip, port string) event.ConnectionEvent {
	return event.ConnectionEvent{
		Time: ts.UTC().Format(time.RFC3339), SrcIP: ip, DstIP: "9.9.9.9",
		DstPort: port, Protocol: "tcp", SrcCC: "US",
	}
}

func TestMigrateFromLegacySchema(t *testing.T) {
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, EventsDBFilename))
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL, dst_port TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
			src_lat REAL NOT NULL DEFAULT 0, src_lon REAL NOT NULL DEFAULT 0,
			dst_lat REAL NOT NULL DEFAULT 0, dst_lon REAL NOT NULL DEFAULT 0,
			src_city TEXT NOT NULL DEFAULT '', dst_city TEXT NOT NULL DEFAULT '',
			src_cc TEXT NOT NULL DEFAULT '', dst_cc TEXT NOT NULL DEFAULT '');
		INSERT INTO events (time, src_ip, dst_ip, dst_port, src_cc)
			VALUES ('2026-01-01T00:00:00Z', '1.2.3.4', '9.9.9.9', '22', 'DE');`)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	edb, err := OpenEventDB(dir)
	if err != nil {
		t.Fatalf("OpenEventDB: %v", err)
	}
	defer edb.Close()

	got, err := edb.LoadHistory(10)
	if err != nil || len(got) != 1 {
		t.Fatalf("LoadHistory = %v, %v", got, err)
	}
	if got[0].DstPort != "22" || got[0].SrcCC != "DE" || got[0].ID != 1 {
		t.Errorf("migrated row wrong: %+v", got[0])
	}
	var typ string
	if err := edb.db.QueryRow(`SELECT typeof(dst_port) FROM events`).Scan(&typ); err != nil || typ != "integer" {
		t.Errorf("dst_port typeof = %q, %v; want integer", typ, err)
	}
}

func TestInsertQueryAndDetails(t *testing.T) {
	dir := t.TempDir()
	edb, err := OpenEventDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e1 := ev(now.Add(-2*time.Hour), "1.1.1.1", "80")
	e2 := ev(now.Add(-time.Minute), "2.2.2.2", "443")
	e2.ClientData = "deadbeef"
	e2.Detail = "GET /.env"
	e2.Tags = []string{"env-probe", "scanner:zgrab"}
	e2.Meta = map[string]string{"ja4": "t13d"}
	e2.ASN = 15169
	e3 := ev(now, "2.2.3.3", "80")
	edb.Insert(e1)
	edb.Insert(e2)
	edb.Insert(e3)
	edb.Close() // drains the write queue

	edb, err = OpenEventDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer edb.Close()

	all, err := edb.QueryHistory(HistoryFilter{}, nil)
	if err != nil || len(all) != 3 {
		t.Fatalf("all = %d, %v", len(all), err)
	}
	if all[0].SrcIP != "1.1.1.1" || all[2].SrcIP != "2.2.3.3" {
		t.Errorf("not oldest-first: %v %v", all[0].SrcIP, all[2].SrcIP)
	}

	// Limit keeps the newest rows.
	lim, _ := edb.QueryHistory(HistoryFilter{Limit: 2}, nil)
	if len(lim) != 2 || lim[0].SrcIP != "2.2.2.2" {
		t.Errorf("limit result wrong: %+v", lim)
	}

	// Filters: tag, ip prefix (with LIKE wildcard escaping), port, ASN.
	for name, tc := range map[string]struct {
		f    HistoryFilter
		want int
	}{
		"tag":        {HistoryFilter{Tag: "env-probe"}, 1},
		"tag-prefix": {HistoryFilter{Tag: "env"}, 0},
		"ip":         {HistoryFilter{IP: "2.2."}, 2},
		"ip-wild":    {HistoryFilter{IP: "2_2"}, 0},
		"port":       {HistoryFilter{Port: "80"}, 2},
		"asn":        {HistoryFilter{ASN: 15169}, 1},
	} {
		got, err := edb.QueryHistory(tc.f, nil)
		if err != nil || len(got) != tc.want {
			t.Errorf("%s: got %d rows (err %v), want %d", name, len(got), err, tc.want)
		}
	}

	d, err := edb.GetEvent(all[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.ClientData != "deadbeef" || d.Detail != "GET /.env" || d.Meta["ja4"] != "t13d" ||
		len(d.Tags) != 2 || d.ASN != 15169 {
		t.Errorf("GetEvent lost fields: %+v", d)
	}
	// List queries must not carry the (large) raw data.
	if all[1].ClientData != "" {
		t.Error("list query should not include client_data")
	}

	n, err := edb.PruneEvents(now.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Errorf("PruneEvents = %d, %v; want 1", n, err)
	}
}
