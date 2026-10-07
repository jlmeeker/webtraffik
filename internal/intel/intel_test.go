package intel

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"webtraffik/internal/event"
)

func TestAnnotateKindAndClass(t *testing.T) {
	cases := []struct {
		name        string
		ev          event.ConnectionEvent
		kind, class string
	}{
		{"connect only", event.ConnectionEvent{Tags: []string{"connect-only"}}, "probe", "scan"},
		{"empty", event.ConnectionEvent{}, "probe", "scan"},
		{"xdp", event.ConnectionEvent{Kind: "observed"}, "observed", "scan"},
		{"exploit", event.ConnectionEvent{ClientData: "41", Tags: []string{"log4shell"}}, "session", "exploit"},
		{"bruteforce", event.ConnectionEvent{Meta: map[string]string{"user": "root", "secret": "x"}}, "session", "bruteforce"},
		{"research tag", event.ConnectionEvent{ClientData: "41", Tags: []string{"scanner:censys"}}, "session", "research"},
		{"known scanner", event.ConnectionEvent{Scanner: "Shodan", Kind: "observed"}, "observed", "research"},
		{"exploit beats scanner", event.ConnectionEvent{Scanner: "Shodan", Tags: []string{"sqli"}, ClientData: "41"}, "session", "exploit"},
		{"plain http", event.ConnectionEvent{ClientData: "47", Tags: []string{"wordpress-probe"}}, "session", "scan"},
	}
	for _, c := range cases {
		ev := c.ev
		Annotate(&ev)
		if ev.Kind != c.kind || ev.Class != c.class {
			t.Errorf("%s: kind/class = %s/%s, want %s/%s", c.name, ev.Kind, ev.Class, c.kind, c.class)
		}
	}
}

func TestFingerprints(t *testing.T) {
	payload := hex.EncodeToString([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"))
	ev := event.ConnectionEvent{ClientData: payload, Meta: map[string]string{"ja4": "t13d", "ja3": "abc"}}
	fp := Fingerprints(&ev)
	if len(fp) != 3 || fp[0] != "ja4:t13d" || fp[1] != "ja3:abc" || fp[2][:3] != "pl:" {
		t.Errorf("fp = %v", fp)
	}
	text := event.ConnectionEvent{ClientData: hex.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))}
	if fp := Fingerprints(&text); len(fp) != 0 {
		t.Errorf("generic HTTP must not fingerprint, got %v", fp)
	}
	hello := event.ConnectionEvent{ClientData: hex.EncodeToString(append([]byte{0x16, 0x03, 0x01}, make([]byte, 60)...))}
	if fp := Fingerprints(&hello); len(fp) != 0 {
		t.Errorf("TLS hello is covered by ja3/ja4, got %v", fp)
	}
	if Fingerprints(&event.ConnectionEvent{ClientData: "zz"}) != nil {
		t.Error("invalid hex should yield nothing")
	}
}

func TestScannerMatching(t *testing.T) {
	if MatchASNOrg("CENSYS-ARIN-01") != "Censys" || MatchASNOrg("Example Net") != "" || MatchASNOrg("") != "" {
		t.Error("ASN org match wrong")
	}
	if MatchRDNS("scan-42.shodan.io.") != "Shodan" || MatchRDNS("evilshodan.io") != "" {
		t.Error("rDNS match wrong (suffix must be a domain boundary)")
	}
}

func TestClusterMergesSharedFingerprints(t *testing.T) {
	now := time.Now()
	rows := []FPRow{
		{IP: "1.1.1.1", FP: []string{"ja4:a", "pl:x"}, Port: 22, CC: "CN", Time: now},
		{IP: "2.2.2.2", FP: []string{"pl:x"}, Port: 23, CC: "US", Time: now.Add(time.Hour)},
		{IP: "3.3.3.3", FP: []string{"ja4:a"}, Port: 22, CC: "CN", Time: now},
		{IP: "4.4.4.4", FP: []string{"ja4:solo"}, Port: 80, Time: now},
		{IP: "5.5.5.5", Port: 80, Time: now}, // no fingerprint
		{IP: "6.6.6.6", FP: []string{"ja4:b", "pl:y"}, Port: 80, Time: now},
		{IP: "7.7.7.7", FP: []string{"ja4:b"}, Port: 80, Time: now},
	}
	cs := Cluster(rows, 2, 10)
	if len(cs) != 2 {
		t.Fatalf("campaigns = %+v", cs)
	}
	if cs[0].IPCount != 3 || len(cs[0].Ports) != 2 || len(cs[0].Countries) != 2 {
		t.Errorf("merged campaign wrong: %+v", cs[0])
	}
	again := Cluster(rows, 2, 10)
	if again[0].ID != cs[0].ID {
		t.Error("campaign id must be deterministic")
	}
	if got := Cluster(rows, 1, 1); len(got) != 1 {
		t.Errorf("limit not applied: %d", len(got))
	}
}

type memStore struct {
	mu sync.Mutex
	m  map[string]Info
}

func (s *memStore) GetIntel(ip string) (Info, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.m[ip]
	return i, ok
}
func (s *memStore) PutIntel(i Info) { s.mu.Lock(); defer s.mu.Unlock(); s.m[i.IP] = i }

func TestResolverForwardConfirmedRDNS(t *testing.T) {
	store := &memStore{m: map[string]Info{}}
	r := NewResolver(Config{RDNS: true, Store: store})
	defer r.Close()
	r.lookup = lookupFuncs{
		addr: func(_ context.Context, ip string) ([]string, error) {
			switch ip {
			case "8.8.4.4":
				return []string{"census1.shodan.io."}, nil
			case "8.8.8.8": // spoofed PTR: forward lookup will not confirm
				return []string{"fake.censys-scanner.com."}, nil
			}
			return nil, nil
		},
		host: func(_ context.Context, name string) ([]string, error) {
			if name == "census1.shodan.io" {
				return []string{"8.8.4.4"}, nil
			}
			return []string{"203.0.113.9"}, nil
		},
	}
	if _, ok := r.Lookup("8.8.4.4"); ok {
		t.Fatal("first lookup must miss (and queue)")
	}
	r.Lookup("8.8.8.8")
	r.Lookup("10.0.0.1") // private: never queued
	waitUntil(t, func() bool { _, ok := r.Lookup("8.8.4.4"); _, ok2 := r.Lookup("8.8.8.8"); return ok && ok2 })
	if in, _ := r.Lookup("8.8.4.4"); in.Scanner != "Shodan" || in.RDNS != "census1.shodan.io" {
		t.Errorf("confirmed = %+v", in)
	}
	if in, _ := r.Lookup("8.8.8.8"); in.Scanner != "" || in.RDNS == "" {
		t.Errorf("spoofed PTR must not yield a scanner: %+v", in)
	}
	if _, ok := store.GetIntel("8.8.4.4"); !ok {
		t.Error("result not persisted")
	}
	if _, ok := r.Get("10.0.0.1"); ok {
		t.Error("private address must not be resolved")
	}
}

func TestResolverAPIs(t *testing.T) {
	gn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("key") != "gk" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"classification":"benign","name":"Censys"}`))
	}))
	defer gn.Close()
	ab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Key") != "ak" || req.URL.Query().Get("ipAddress") != "8.8.4.4" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"data":{"abuseConfidenceScore":88}}`))
	}))
	defer ab.Close()

	r := NewResolver(Config{GreyNoiseKey: "gk", AbuseKey: "ak"})
	defer r.Close()
	r.greyNoiseURL, r.abuseURL = gn.URL+"/", ab.URL
	r.Lookup("8.8.4.4")
	waitUntil(t, func() bool { _, ok := r.Lookup("8.8.4.4"); return ok })
	in, _ := r.Lookup("8.8.4.4")
	if in.GreyNoise != "benign" || in.Scanner != "Censys" || in.AbuseScore != 88 {
		t.Errorf("api intel = %+v", in)
	}
}

func TestResolverDisabledIsInert(t *testing.T) {
	r := NewResolver(Config{})
	defer r.Close()
	if _, ok := r.Lookup("8.8.8.8"); ok {
		t.Error("disabled resolver should never hit")
	}
	r.Close() // idempotent
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
