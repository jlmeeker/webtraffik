package db

import (
	"errors"
	"testing"
	"time"

	"webtraffik/internal/event"
)

func seed(t *testing.T) (*EventDB, time.Time) {
	t.Helper()
	edb, err := OpenEventDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(edb.Close)
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	mk := func(age time.Duration, ip, port, cc, user, secret string, tags []string, kind, class, fp string) event.ConnectionEvent {
		e := ev(now.Add(-age), ip, port)
		e.SrcCC, e.Tags, e.Kind, e.Class = cc, tags, kind, class
		e.ASN, e.ASNOrg = 64500, "Example Net"
		e.Meta = map[string]string{"user": user, "secret": secret}
		if fp != "" {
			e.FP = []string{fp}
		}
		return e
	}
	bare := ev(now.Add(-time.Hour), "9.9.9.1", "9999") // no meta: stored as ''
	bare.Kind = "observed"
	edb.flushBatch([]event.ConnectionEvent{
		bare,
		mk(time.Hour, "1.1.1.1", "22", "CN", "root", "123456", []string{"mirai-default-creds"}, "session", "bruteforce", "ja4:aaa"),
		mk(2*time.Hour, "2.2.2.2", "22", "CN", "root", "admin", nil, "session", "bruteforce", "ja4:aaa"),
		mk(3*time.Hour, "3.3.3.3", "23", "US", "admin", "admin", nil, "session", "bruteforce", "pl:zzz"),
		mk(30*time.Hour, "1.1.1.1", "22", "CN", "root", "toor", []string{"x"}, "probe", "scan", ""), // previous period
	})
	return edb, now
}

func TestParseQueryAndSearch(t *testing.T) {
	edb, now := seed(t)
	cases := []struct {
		q    string
		want int
	}{
		{"port:22", 3},
		{"port:22 since:24h", 2},
		{"-port:22", 2},
		{"cc:cn -port:23", 3},
		{`user:root class:bruteforce`, 2},
		{"tag:mirai-default-creds", 1},
		{"kind:probe", 1},
		{`"Example Net"`, 4},
		{"kind:observed", 1},
		{"asn:AS64500 -cc:CN", 1},
		{"ip:3.3", 1},
		{"ip:3.3 ip:2.2", 2},
		{"ip:3.3 port:22", 0},
	}
	for _, c := range cases {
		conds, err := ParseQuery(c.q, now)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		got, err := edb.QueryHistory(HistoryFilter{Conds: conds}, nil)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if len(got) != c.want {
			t.Errorf("%q = %d events, want %d", c.q, len(got), c.want)
		}
	}
}

func TestParseQueryErrors(t *testing.T) {
	now := time.Now()
	for _, q := range []string{`"open`, "port:abc", "port:70000", "bogus:1", "cc:usa", "since:xyz", "asn:x", "port:"} {
		_, err := ParseQuery(q, now)
		var se *SearchError
		if !errors.As(err, &se) {
			t.Errorf("%q: err = %v, want SearchError", q, err)
		}
	}
	// Things that look like keys but are plain text must not error.
	for _, q := range []string{"2001:db8::1", "http://x.test", "10.0.0.1:80", "-"} {
		if _, err := ParseQuery(q, now); err != nil {
			t.Errorf("%q: unexpected %v", q, err)
		}
	}
	long := ""
	for i := 0; i < 25; i++ {
		long += "a "
	}
	if _, err := ParseQuery(long, now); err == nil {
		t.Error("expected too-many-terms error")
	}
}

func TestSearchEscapesWildcards(t *testing.T) {
	edb, now := seed(t)
	conds, _ := ParseQuery("%", now)
	got, _ := edb.QueryHistory(HistoryFilter{Conds: conds}, nil)
	if len(got) != 0 {
		t.Errorf("'%%' matched %d events; wildcards must be escaped", len(got))
	}
}

func TestTopN(t *testing.T) {
	edb, now := seed(t)
	r, err := edb.TopN("credentials", 24, 10, now)
	if err != nil || len(r.Items) != 3 {
		t.Fatalf("credentials = %+v, %v", r, err)
	}
	r, _ = edb.TopN("usernames", 24, 10, now)
	if r.Items[0].Key != "root" || r.Items[0].Count != 2 || r.Items[0].IPs != 2 || r.Items[0].Prev != 1 {
		t.Errorf("usernames[0] = %+v", r.Items[0])
	}
	if d := r.Items[0].DeltaPct; d == nil || *d != 100 {
		t.Errorf("delta = %v, want 100", d)
	}
	if r.Items[1].DeltaPct != nil { // "admin": no previous period
		t.Errorf("new item should have nil delta: %+v", r.Items[1])
	}
	r, _ = edb.TopN("tags", 24, 10, now)
	if len(r.Items) != 1 || r.Items[0].Key != "mirai-default-creds" {
		t.Errorf("tags = %+v", r.Items)
	}
	r, _ = edb.TopN("asns", 24, 10, now)
	if len(r.Items) != 1 || r.Items[0].Key != "AS64500 Example Net" || r.Items[0].Count != 3 {
		t.Errorf("asns = %+v", r.Items)
	}
	if _, err := edb.TopN("nope", 24, 10, now); err == nil {
		t.Error("unknown dimension should error")
	}
	for _, d := range TopDimensions() { // every advertised dimension must run
		if _, err := edb.TopN(d, 24, 5, now); err != nil {
			t.Errorf("TopN(%s): %v", d, err)
		}
	}
}

func TestCampaignsAndIntelStore(t *testing.T) {
	edb, now := seed(t)
	cs, err := edb.Campaigns(72, 10, now)
	if err != nil || len(cs) != 1 {
		t.Fatalf("campaigns = %+v, %v", cs, err)
	}
	if cs[0].IPCount != 2 || cs[0].Label != "ja4:aaa" || cs[0].Ports[0] != 22 {
		t.Errorf("campaign = %+v", cs[0])
	}

	if _, ok := edb.GetIntel("8.8.8.8"); ok {
		t.Error("unexpected intel hit")
	}
	edb.PutIntel(intelInfo("8.8.8.8"))
	if in, ok := edb.GetIntel("8.8.8.8"); !ok || in.Scanner != "Shodan" || in.AbuseScore != 7 {
		t.Errorf("intel = %+v, %v", in, ok)
	}
}
