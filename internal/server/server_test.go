package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"webtraffik/internal/app"
	"webtraffik/internal/db"
	"webtraffik/internal/ebpf"
	"webtraffik/internal/event"
	"webtraffik/internal/geo"
	"webtraffik/internal/server"
	"webtraffik/internal/services"
	"webtraffik/internal/testutil"
)

type harness struct {
	app    *app.App
	ts     *httptest.Server
	cancel context.CancelFunc
	done   chan error
	dir    string
}

func start(t *testing.T, cfg server.Config) *harness {
	t.Helper()
	dir := t.TempDir()
	cityPath := filepath.Join(dir, geo.CityFilename)
	testutil.WriteCityDB(t, cityPath)

	disabled := map[int]bool{}
	for _, s := range services.All() {
		disabled[s.Port] = true // bind nothing
	}
	a, err := app.New(app.Options{
		DataDir: dir, CaptureMode: ebpf.ModeGoOnly, DisabledPort: disabled,
		DisableRgeo: true, DisableASN: true,
		GeoCity:  geo.Source{Path: cityPath},
		PublicIP: "192.0.2.50", MaxConns: 8, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{app: a, cancel: cancel, done: make(chan error, 1), dir: dir}
	go func() { h.done <- a.Run(ctx) }()

	cfg.Static = fstest.MapFS{"index.html": {Data: []byte("<h1>ui</h1>")}}
	h.ts = httptest.NewServer(server.New(a, cfg).Handler())
	t.Cleanup(func() {
		h.ts.Close()
		cancel()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("app.Run did not return after cancel")
		}
	})
	return h
}

func (h *harness) get(t *testing.T, path string, hdr ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", h.ts.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *harness) post(t *testing.T, path, body string, hdr ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", h.ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPipelineAPIAndWebSocket(t *testing.T) {
	h := start(t, server.Config{})

	// A live WebSocket client connected BEFORE the capture.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(h.ts.URL, "http") + "/ws?hours=1"
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	waitFor(t, "ws subscription", func() bool { return h.app.Hub.Subscribers() == 1 })

	h.app.Submit(services.Capture{
		SrcIP: "203.0.113.7", DstPort: "22", Protocol: "tcp",
		Data: []byte("SSH-2.0-test"), Detail: "ssh login root:toor", Tags: []string{"credential-attempt"},
		Meta: map[string]string{"user": "root"},
	})

	var ev event.ConnectionEvent
	if err := wsjson.Read(ctx, conn, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SrcCity != "Berlin" || ev.SrcCC != "DE" || ev.DstCC != "US" || ev.DstIP != "192.0.2.50" {
		t.Errorf("enrichment wrong: %+v", ev)
	}
	if ev.Detail != "ssh login root:toor" || ev.Meta["user"] != "root" || ev.ClientData == "" || ev.Replay {
		t.Errorf("capture fields lost: %+v", ev)
	}

	// /api/recent reflects it.
	_, body := h.get(t, "/api/recent")
	var recent []event.ConnectionEvent
	json.Unmarshal([]byte(body), &recent)
	if len(recent) != 1 || recent[0].SrcIP != "203.0.113.7" {
		t.Errorf("recent = %s", body)
	}

	// Persisted to the DB: visible in /api/history and /api/event.
	waitFor(t, "history row", func() bool {
		_, b := h.get(t, "/api/history?tag=credential-attempt")
		var hist []event.ConnectionEvent
		json.Unmarshal([]byte(b), &hist)
		if len(hist) != 1 {
			return false
		}
		if hist[0].ClientData != "" {
			t.Error("history list must omit client_data")
		}
		code, one := h.get(t, "/api/event?id="+itoa(hist[0].ID))
		var full event.ConnectionEvent
		json.Unmarshal([]byte(one), &full)
		return code == 200 && full.ClientData != ""
	})

	// A replaying client sees it flagged as history.
	conn2, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")
	var re event.ConnectionEvent
	if err := wsjson.Read(ctx, conn2, &re); err != nil || !re.Replay {
		t.Errorf("replay event = %+v, %v", re, err)
	}

	// Status and misc endpoints.
	_, st := h.get(t, "/api/status")
	if !strings.Contains(st, `"events_handled":1`) || !strings.Contains(st, `"version":"test"`) {
		t.Errorf("status = %s", st)
	}
	for _, p := range []string{"/", "/api/self", "/api/services", "/api/ports", "/api/banned", "/api/scanners", "/api/metrics", "/metrics", "/healthz"} {
		if code, _ := h.get(t, p); code != 200 {
			t.Errorf("GET %s = %d", p, code)
		}
	}
	if code, hdrs := h.get(t, "/"); code != 200 || hdrs == "" {
		t.Error("static not served")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestAuth(t *testing.T) {
	h := start(t, server.Config{User: "ops", Pass: "s3cret"})
	if code, _ := h.get(t, "/api/self"); code != 401 {
		t.Errorf("no creds = %d, want 401", code)
	}
	if code, _ := h.get(t, "/healthz"); code != 200 {
		t.Errorf("/healthz must be open for probes, got %d", code)
	}
	req, _ := http.NewRequest("GET", h.ts.URL+"/api/self", nil)
	req.SetBasicAuth("ops", "wrong")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong password = %d", resp.StatusCode)
	}
	req.SetBasicAuth("ops", "s3cret")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("right password = %d", resp.StatusCode)
	}
}

func TestBanAPIValidationAndCSRF(t *testing.T) {
	h := start(t, server.Config{})

	if code, body := h.post(t, "/api/ban", `{"ip":"203.0.113.9","port":"22"}`); code != 200 || !strings.Contains(body, "banned") {
		t.Errorf("ban = %d %s", code, body)
	}
	if !h.app.Limiter.IsBanned("203.0.113.9", "22") {
		t.Error("IP not banned")
	}
	if code, _ := h.post(t, "/api/ban", `{"ip":"203.0.113.9","port":"22"}`); code != 409 {
		t.Errorf("duplicate ban = %d, want 409", code)
	}
	for name, body := range map[string]string{
		"garbage ip":  `{"ip":"nope","port":"22"}`,
		"loopback":    `{"ip":"127.0.0.1","port":"22"}`,
		"unspecified": `{"ip":"0.0.0.0","port":"22"}`,
		"bad port":    `{"ip":"1.2.3.4","port":"99999"}`,
		"port zero":   `{"ip":"1.2.3.4","port":"0"}`,
		"not json":    `ip=1.2.3.4`,
	} {
		if code, _ := h.post(t, "/api/ban", body); code != 400 {
			t.Errorf("%s: code = %d, want 400", name, code)
		}
	}
	// Cross-origin POST (CSRF) is refused; same-origin is accepted.
	if code, _ := h.post(t, "/api/ban", `{"ip":"203.0.113.10","port":"22"}`, "Origin", "https://evil.example"); code != 403 {
		t.Errorf("cross-origin POST = %d, want 403", code)
	}
	if h.app.Limiter.IsBanned("203.0.113.10", "22") {
		t.Error("cross-origin request must not ban")
	}
	if code, _ := h.post(t, "/api/ban", `{"ip":"203.0.113.10","port":"22"}`, "Origin", h.ts.URL); code != 200 {
		t.Errorf("same-origin POST = %d, want 200", code)
	}
	// Non-JSON content type is refused (forces a CORS preflight for browsers).
	req, _ := http.NewRequest("POST", h.ts.URL+"/api/unban", strings.NewReader(`{"ip":"203.0.113.9","port":"22"}`))
	req.Header.Set("Content-Type", "text/plain")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST = %d", resp.StatusCode)
	}
	if code, _ := h.post(t, "/api/unban", `{"ip":"203.0.113.9","port":"22"}`); code != 200 {
		t.Errorf("unban = %d", code)
	}
	// Methods.
	if code, _ := h.get(t, "/api/ban"); code != 405 {
		t.Errorf("GET /api/ban = %d, want 405", code)
	}
}

func TestWebSocketRejectsForeignOrigin(t *testing.T) {
	h := start(t, server.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(h.ts.URL, "http") + "/ws"
	_, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {"https://evil.example"}}})
	if err == nil {
		t.Error("cross-origin WebSocket must be refused")
	}
}

func TestTracerouteValidation(t *testing.T) {
	h := start(t, server.Config{})
	for _, ip := range []string{"", "x", "10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "::1"} {
		if code, _ := h.get(t, "/api/traceroute?ip="+ip); code != 400 {
			t.Errorf("traceroute ip=%q = %d, want 400", ip, code)
		}
	}
}

func TestGracefulShutdownPersistsEvents(t *testing.T) {
	dir := t.TempDir()
	cityPath := filepath.Join(dir, geo.CityFilename)
	testutil.WriteCityDB(t, cityPath)
	disabled := map[int]bool{}
	for _, s := range services.All() {
		disabled[s.Port] = true
	}
	a, err := app.New(app.Options{DataDir: dir, CaptureMode: ebpf.ModeGoOnly, DisabledPort: disabled,
		DisableRgeo: true, DisableASN: true, GeoCity: geo.Source{Path: cityPath}, PublicIP: "none"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	for i := 0; i < 200; i++ {
		a.Submit(services.Capture{SrcIP: "198.51.100.4", DstPort: "80", Protocol: "udp"}) // udp: skips rate limiting
	}
	cancel() // immediately: queued work must still be drained and flushed
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	a.Submit(services.Capture{SrcIP: "198.51.100.4", DstPort: "80", Protocol: "udp"}) // after shutdown: must not panic

	edb, err := db.OpenEventDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer edb.Close()
	got, _ := edb.QueryHistory(db.HistoryFilter{}, nil)
	if len(got) != 200 {
		t.Errorf("persisted %d events after shutdown, want 200", len(got))
	}
}

func TestDNSRebindingHostCheckWhenUnauthenticated(t *testing.T) {
	h := start(t, server.Config{AllowedOrigins: []string{"dash.example.org"}})
	for host, want := range map[string]int{
		"127.0.0.1:8999": 200, "localhost:8999": 200, "[::1]:8999": 200,
		"192.168.1.5:8999": 200, "dash.example.org": 200,
		"evil.example.com:8999": 403, "attacker.test": 403,
	} {
		req, _ := http.NewRequest("GET", h.ts.URL+"/api/self", nil)
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %q = %d, want %d", host, resp.StatusCode, want)
		}
	}
	// With auth enabled the Host restriction is not applied.
	h2 := start(t, server.Config{User: "u", Pass: "p"})
	req, _ := http.NewRequest("GET", h2.ts.URL+"/healthz", nil)
	req.Host = "anything.example"
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("auth-enabled host = %d", resp.StatusCode)
	}
}

func TestSearchTopCampaignsIntelAPI(t *testing.T) {
	h := start(t, server.Config{})
	hello := make([]byte, 40)
	for i := range hello {
		hello[i] = byte(i + 1) // binary payload -> payload fingerprint
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		h.app.Submit(services.Capture{
			SrcIP: ip, DstPort: "22", Protocol: "tcp", Data: hello,
			Detail: "ssh login root", Meta: map[string]string{"user": "root", "secret": "toor", "ja4": "t13d-test"},
		})
	}
	h.app.Submit(services.Capture{SrcIP: "203.0.113.9", DstPort: "9999", Protocol: "udp", Kind: event.KindObserved})
	waitFor(t, "rows stored", func() bool {
		_, b := h.get(t, "/api/history")
		var hist []event.ConnectionEvent
		json.Unmarshal([]byte(b), &hist)
		return len(hist) == 3
	})

	_, b := h.get(t, "/api/history?q=user:root+class:bruteforce")
	var hist []event.ConnectionEvent
	json.Unmarshal([]byte(b), &hist)
	if len(hist) != 2 || hist[0].Kind != "session" || hist[0].Class != "bruteforce" {
		t.Errorf("q search = %s", b)
	}
	if _, b = h.get(t, "/api/history?kind=observed"); !strings.Contains(b, `"kind":"observed"`) || !strings.Contains(b, "203.0.113.9") {
		t.Errorf("kind filter = %s", b)
	}
	if code, b := h.get(t, "/api/history?q=bogus:1"); code != 400 || !strings.Contains(b, "unknown key") {
		t.Errorf("bad query = %d %s", code, b)
	}

	_, b = h.get(t, "/api/top?by=usernames&hours=1")
	if !strings.Contains(b, `"key":"root"`) || !strings.Contains(b, `"count":2`) || !strings.Contains(b, `"ips":2`) {
		t.Errorf("top = %s", b)
	}
	if code, _ := h.get(t, "/api/top?by=nope"); code != 400 {
		t.Errorf("top bad dim = %d", code)
	}
	_, b = h.get(t, "/api/campaigns")
	if !strings.Contains(b, `"ip_count":2`) || !strings.Contains(b, "ja4:t13d-test") {
		t.Errorf("campaigns = %s", b)
	}
	if code, b := h.get(t, "/api/intel?ip=203.0.113.7"); code != 200 || !strings.Contains(b, "203.0.113.7") {
		t.Errorf("intel = %d %s", code, b)
	}
	if code, _ := h.get(t, "/api/intel?ip=nope"); code != 400 {
		t.Errorf("intel bad ip = %d", code)
	}
}
