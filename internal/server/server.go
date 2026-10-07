// Package server serves the dashboard UI and JSON/WebSocket/SSE API.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"webtraffik/internal/app"
	"webtraffik/internal/db"
	"webtraffik/internal/event"
	"webtraffik/internal/ratelimit"
	"webtraffik/internal/services"
	"webtraffik/internal/traceroute"
)

// Config configures the dashboard server.
type Config struct {
	Listen         string   // e.g. ":8999" or "127.0.0.1:8999"
	User, Pass     string   // HTTP Basic credentials; empty disables auth
	AllowedOrigins []string // extra Origin hosts accepted for WebSocket and POST (e.g. a reverse proxy name)
	Static         fs.FS    // embedded UI
}

// Server is the dashboard HTTP server.
type Server struct {
	app      *app.App
	cfg      Config
	traceSem chan struct{}
	userHash [32]byte
	passHash [32]byte
}

// New builds a Server.
func New(a *app.App, cfg Config) *Server {
	s := &Server{app: a, cfg: cfg, traceSem: make(chan struct{}, 2)}
	s.userHash = sha256.Sum256([]byte(cfg.User))
	s.passHash = sha256.Sum256([]byte(cfg.Pass))
	return s
}

// AuthEnabled reports whether HTTP Basic auth is required.
func (s *Server) AuthEnabled() bool { return s.cfg.User != "" || s.cfg.Pass != "" }

// Serve listens until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dashboard listen on %s: %w", s.cfg.Listen, err)
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves on an existing listener.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		// No WriteTimeout: SSE and WebSocket responses are long-lived.
	}
	if !s.AuthEnabled() {
		slog.Warn("dashboard has NO authentication; keep it firewalled or set dashboard-user/dashboard-pass", "listen", ln.Addr().String())
	}
	slog.Info("dashboard listening", "addr", ln.Addr().String(), "auth", s.AuthEnabled())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close() // force-close lingering WebSockets / SSE streams
	}
	return nil
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	if s.cfg.Static != nil {
		mux.Handle("/", http.FileServer(http.FS(s.cfg.Static)))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	mux.HandleFunc("/api/self", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.app.Self) })
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.app.Status()) })
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/event", s.handleEvent)
	mux.HandleFunc("/api/recent", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, nonNil(s.app.Hub.Snapshot()))
	})
	mux.HandleFunc("/api/banned", func(w http.ResponseWriter, r *http.Request) {
		bans := s.app.Limiter.ActiveBans()
		if bans == nil {
			bans = []ratelimit.BanEntry{}
		}
		writeJSON(w, bans)
	})
	mux.HandleFunc("/api/scanners", func(w http.ResponseWriter, r *http.Request) {
		sc := s.app.Limiter.ActiveScanners()
		if sc == nil {
			sc = []ratelimit.ScannerEntry{}
		}
		writeJSON(w, sc)
	})
	mux.HandleFunc("/api/ban", s.handleBan(true))
	mux.HandleFunc("/api/unban", s.handleBan(false))
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/ports", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, services.All()) })
	mux.HandleFunc("/api/traceroute", s.handleTraceroute)
	mux.HandleFunc("/api/metrics", s.app.Metrics.HandleMetrics)
	mux.HandleFunc("/metrics", s.app.Metrics.HandleMetricsPrometheus)
	mux.HandleFunc("/api/ebpf/stats", s.app.EBPF.StatsHandler())
	mux.HandleFunc("/ws", s.handleWS)

	return recoverMW(securityHeaders(s.hostCheck(s.originCheck(s.basicAuth(mux)))))
}

// ── middleware ────────────────────────────────────────────────────────────────

func recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				slog.Error("handler panic", "path", r.URL.Path, "panic", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Everything is self-hosted (no CDN). Inline styles are allowed for the
		// SVG map; scripts must come from this origin.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) basicAuth(next http.Handler) http.Handler {
	if !s.AuthEnabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		// Compare hashes (fixed length) in constant time; evaluate both.
		okU := subtle.ConstantTimeCompare(uh[:], s.userHash[:])
		okP := subtle.ConstantTimeCompare(ph[:], s.passHash[:])
		if !ok || okU&okP != 1 {
			time.Sleep(400 * time.Millisecond) // blunt online guessing
			w.Header().Set("WWW-Authenticate", `Basic realm="webTraffik", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck defends an unauthenticated dashboard against DNS rebinding: a
// hostile page can make its own domain resolve to the dashboard's IP, which
// would make Origin == Host and defeat the origin checks. Requests must
// therefore name the server by IP literal, "localhost", or an allowed host.
// When Basic auth is enabled the browser will not send credentials to the
// attacker's domain, so no host restriction is applied.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	if s.AuthEnabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "unrecognised Host header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	for _, a := range s.cfg.AllowedOrigins {
		if strings.EqualFold(a, host) || strings.EqualFold(a, hostport) {
			return true
		}
	}
	return false
}

// originCheck blocks cross-site state-changing requests: any request carrying
// an Origin header whose host is neither this server's Host nor an allowed
// origin is refused for non-GET methods. (The WebSocket handshake performs its
// own origin check.) POST bodies must be JSON, which forces a CORS preflight
// for cross-origin callers.
func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(o, r.Host) {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, host) {
		return true
	}
	for _, a := range s.cfg.AllowedOrigins {
		if strings.EqualFold(a, u.Host) || strings.EqualFold(a, u.Hostname()) {
			return true
		}
	}
	return false
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("write json", "err", err)
	}
}

func nonNil(e []event.ConnectionEvent) []event.ConnectionEvent {
	if e == nil {
		return []event.ConnectionEvent{}
	}
	return e
}

// ── handlers ──────────────────────────────────────────────────────────────────

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// GET /api/history?country=&ip=&port=&service=&tag=&asn=&date_from=&date_to=&limit=&offset=
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.HistoryFilter{
		Country: q.Get("country"), IP: q.Get("ip"), Port: q.Get("port"), Service: q.Get("service"),
		DateFrom: q.Get("date_from"), DateTo: q.Get("date_to"), Tag: q.Get("tag"),
		Limit: atoiDefault(q.Get("limit"), 0), Offset: atoiDefault(q.Get("offset"), 0),
	}
	if a := atoiDefault(q.Get("asn"), 0); a > 0 {
		f.ASN = uint32(a)
	}
	events, err := s.app.DB.QueryHistory(f, services.PortsForService)
	if err != nil {
		slog.Error("history query", "err", err)
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, nonNil(events))
}

// GET /api/event?id=N — one event including raw client data.
func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	ev, err := s.app.DB.GetEvent(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, ev)
}

type banRequest struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
}

// parseBanRequest validates and canonicalises an ip/port pair.
func parseBanRequest(r *http.Request) (banRequest, error) {
	var req banRequest
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, errors.New("invalid JSON body")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil {
		return req, errors.New("invalid ip")
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
		return req, errors.New("ip not bannable")
	}
	req.IP = addr.String()
	if p, err := strconv.Atoi(req.Port); err != nil || p < 1 || p > 65535 {
		return req, errors.New("invalid port")
	}
	return req, nil
}

func (s *Server) handleBan(ban bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req, err := parseBanRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var ok bool
		status := map[bool][2]string{true: {"banned", "already_banned"}, false: {"unbanned", "not_banned"}}[ban]
		failCode := http.StatusConflict
		if ban {
			ok = s.app.Limiter.ManualBan(req.IP, req.Port)
			if ok {
				slog.Info("manual ban", "ip", req.IP, "port", req.Port)
			}
		} else {
			ok = s.app.Limiter.ManualUnban(req.IP, req.Port)
			failCode = http.StatusNotFound
			if ok {
				slog.Info("manual unban", "ip", req.IP, "port", req.Port)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if ok {
			json.NewEncoder(w).Encode(map[string]string{"status": status[0]})
			return
		}
		w.WriteHeader(failCode)
		json.NewEncoder(w).Encode(map[string]string{"status": status[1]})
	}
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Name  string `json:"name"`
		Ports []int  `json:"ports"`
	}
	names := services.AllServiceNames()
	out := make([]entry, 0, len(names))
	for n, p := range names {
		out = append(out, entry{n, p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, out)
}

// cgnat is 100.64.0.0/10, which netip does not treat as private.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !a.IsLinkLocalUnicast() && !cgnat.Contains(a)
}

// GET /api/traceroute?ip= — Server-Sent Events, one traceroute.Hop per event.
func (s *Server) handleTraceroute(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil || !isPublic(addr) {
		http.Error(w, "ip must be a public IP address", http.StatusBadRequest)
		return
	}
	ip := addr.Unmap().String()
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	select {
	case s.traceSem <- struct{}{}:
		defer func() { <-s.traceSem }()
	default:
		http.Error(w, "too many concurrent traceroutes", http.StatusTooManyRequests)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	geoFn := func(ipStr string) (lat, lon float64, city, cc string, accuracyKm uint16) {
		loc, err := s.app.Geo.Lookup(ipStr)
		if err != nil || loc == nil {
			return 0, 0, "", "", 0
		}
		return loc.Lat, loc.Lon, loc.City, loc.CountryCode, loc.AccuracyRadius
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	hopCh := make(chan traceroute.Hop, 32)
	go traceroute.Run(ctx, ip, 20, geoFn, hopCh)

	for hop := range hopCh {
		data, err := json.Marshal(hop)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		fl.Flush()
	}
	fmt.Fprint(w, "event: done\ndata: {}\n\n")
	fl.Flush()
}

const (
	maxReplayEvents = 50000
	wsWriteTimeout  = 10 * time.Second
	wsPingInterval  = 30 * time.Second
)

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.cfg.AllowedOrigins})
	if err != nil {
		slog.Debug("websocket accept", "err", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	ctx := conn.CloseRead(r.Context())

	// Subscribe first so live events buffer while history replays.
	ch := s.app.Hub.Subscribe()
	defer s.app.Hub.Unsubscribe(ch)

	hours := 1
	if n, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && n >= 1 && n <= 24 {
		hours = n
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)

	write := func(ev event.ConnectionEvent) error {
		wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
		defer cancel()
		return wsjson.Write(wctx, conn, ev)
	}

	history, err := s.app.DB.LoadHistorySince(since, maxReplayEvents)
	if err != nil {
		slog.Warn("websocket history", "err", err)
	}
	for _, ev := range history {
		ev.Replay = true
		if write(ev) != nil {
			return
		}
	}

	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()
	for {
		select {
		case ev := <-ch:
			if write(ev) != nil {
				return
			}
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
