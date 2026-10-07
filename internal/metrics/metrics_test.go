package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webtraffik/internal/db"
	"webtraffik/internal/event"
)

func TestRecordAndPrometheus(t *testing.T) {
	edb, err := db.OpenEventDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer edb.Close()
	mc := NewCache(edb, func(p string) string { return "svc" + p })
	mc.Record(event.ConnectionEvent{SrcIP: "1.1.1.1", DstPort: "22", Protocol: "tcp", SrcCC: "DE", Tags: []string{"log4shell", "scanner:zgrab"}})
	mc.Record(event.ConnectionEvent{SrcIP: "1.1.1.2", DstPort: "22", Protocol: "tcp", SrcCC: "DE", Tags: []string{"log4shell"}})
	mc.RecordBan("auto")
	mc.Close() // final flush

	mc2 := NewCache(edb, func(p string) string { return "svc" + p })
	defer mc2.Close()
	rr := httptest.NewRecorder()
	mc2.HandleMetricsPrometheus(rr, httptest.NewRequest("GET", "/metrics?from="+time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339), nil))
	body := rr.Body.String()
	for _, want := range []string{
		`webtraffik_connections{cc="DE",port="22",protocol="tcp",service="svc22"} 2`,
		`webtraffik_tag_hits{tag="log4shell"} 2`,
		`webtraffik_tag_hits{tag="scanner:zgrab"} 1`,
		`webtraffik_bans{type="auto"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}
