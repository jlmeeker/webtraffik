package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"webtraffik/internal/db"
	"webtraffik/internal/ebpf"
	"webtraffik/internal/event"
	"webtraffik/internal/geo"
	"webtraffik/internal/iputil"
	"webtraffik/internal/metrics"
	"webtraffik/internal/ratelimit"
	"webtraffik/internal/services"
	"webtraffik/internal/traceroute"
)

// ── hub ──────────────────────────────────────────────────────────────────────

const historySize = 1000

// hub manages WebSocket subscribers and a rolling history buffer.
type hub struct {
	mu          sync.Mutex
	subscribers map[chan event.ConnectionEvent]struct{}
	history     []event.ConnectionEvent // ring buffer, capped at historySize
}

func newHub() *hub {
	return &hub{
		subscribers: make(map[chan event.ConnectionEvent]struct{}),
		history:     make([]event.ConnectionEvent, 0, historySize),
	}
}

func (h *hub) subscribe() chan event.ConnectionEvent {
	ch := make(chan event.ConnectionEvent, 256)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan event.ConnectionEvent) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
}

// snapshot returns a copy of the current history slice, oldest-first.
func (h *hub) snapshot() []event.ConnectionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]event.ConnectionEvent, len(h.history))
	copy(out, h.history)
	return out
}

func (h *hub) broadcast(ev event.ConnectionEvent) {
	h.mu.Lock()
	// Append to history, evict oldest when full.
	if len(h.history) >= historySize {
		h.history = append(h.history[1:], ev)
	} else {
		h.history = append(h.history, ev)
	}
	// Snapshot subscriber channels under lock, then release before sending.
	subs := make([]chan event.ConnectionEvent, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	// Fan-out without holding the lock — subscribe/unsubscribe are not blocked.
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// ── application globals ───────────────────────────────────────────────────────

var (
	appHub     = newHub()
	appDB      *db.EventDB
	appGeo     *geo.GeoLocator
	appMetrics *metrics.Cache
	appLimiter *ratelimit.Limiter
	appEBPF    *ebpf.Manager
	selfIP     string
	selfLat    float64
	selfLon    float64
	selfCity   string
	selfCC     string
)

// capturePorts are the common non-TLS HTTP ports the app listens on directly.
// Point your firewall NAT rules at these same ports.
var capturePorts = []int{
	80,   // HTTP standard
	8080, // Alt HTTP / proxies
	8000, // Django, Python http.server
	8008, // Alt HTTP, IoT/home automation
	8081, // Alt proxy, Nexus
	8088, // Alt HTTP
	8090, // Confluence, misc
	8888, // Jupyter Notebook
	3000, // Node/Express, Grafana, Rails
	3001, // React dev, alt 3000
	3128, // Squid proxy
	4000, // Phoenix (Elixir)
	4200, // Angular dev
	5000, // Flask, Docker registry
	5001, // IPFS, alt Flask
	9000, // SonarQube, Portainer
	9090, // Prometheus, Cockpit
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	log.Println("webTraffik starting...")

	// -config flag must be parsed before flag.Parse() so we can load the config
	// file and use it as the default source for all other flags.
	// We do a lightweight pre-scan of os.Args rather than registering -config
	// with the flag package (which would require two Parse passes).
	configPath := ""
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "-config" || arg == "--config" {
			if i+1 < len(args) {
				configPath = args[i+1]
			}
		} else if len(arg) > 8 && arg[:8] == "-config=" {
			configPath = arg[8:]
		} else if len(arg) > 9 && arg[:9] == "--config=" {
			configPath = arg[9:]
		}
	}

	// Load config file (silent no-op if the file does not exist).
	cfgPath := resolveConfigPath(configPath)
	var cfg Config
	if cfgPath != "" {
		var cfgErr error
		cfg, cfgErr = loadConfig(cfgPath)
		if cfgErr != nil {
			log.Fatalf("config: failed to load %q: %v", cfgPath, cfgErr)
		}
	}

	// Register CLI flags. Defaults come from the config file where set.
	captureModeDef := "hybrid"
	if cfg.CaptureMode != "" {
		captureModeDef = cfg.CaptureMode
	}
	disablePortsDef := cfg.DisablePorts
	mgmtPortsDef := "8999,22"
	if cfg.MgmtPorts != "" {
		mgmtPortsDef = cfg.MgmtPorts
	}

	disablePortsFlag := flag.String("disable-ports", disablePortsDef,
		"Comma-separated list of ports to skip binding (e.g. 22,80,443). "+
			"These ports will not be listened on. Update your firewall rules accordingly.")
	disableRgeo := flag.Bool("disable-rgeo", cfg.DisableRgeo,
		"Skip loading the rgeo reverse geocoder (saves ~2 min startup on slow hardware). "+
			"City names will be missing for ~5-10%% of IPs where MaxMind has no city data.")
	captureModeFlag := flag.String("capture-mode", captureModeDef,
		`Capture mode: "hybrid" (default, eBPF bans + Go listeners), `+
			`"ebpf-only" (XDP telemetry, no Go listeners), `+
			`"go-only" (pure userspace, no eBPF).`)
	ebpfIfaceFlag := flag.String("ebpf-iface", cfg.EBPFIface,
		"Network interface for eBPF XDP attach (default: auto-detect from default route).")
	mgmtPortsFlag := flag.String("mgmt-ports", mgmtPortsDef,
		"Comma-separated management ports that bypass eBPF ban enforcement and telemetry.")
	mgmtAllowFileFlag := flag.String("mgmt-allow-file", cfg.MgmtAllowFile,
		"Path to file listing allowed management IPs, one IPv4 per line (optional).")
	// -config is documented here so it appears in -help output.
	flag.String("config", "",
		"Path to YAML config file (default: /etc/webtraffik/config.yaml if it exists). "+
			"CLI flags always override config file values.")
	flag.Parse()

	// Build a set of disabled ports from the flag value.
	disabledPorts := make(map[int]bool)
	if *disablePortsFlag != "" {
		for _, tok := range strings.Split(*disablePortsFlag, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			p, err := strconv.Atoi(tok)
			if err != nil {
				log.Fatalf("Invalid port in -disable-ports: %q", tok)
			}
			disabledPorts[p] = true
			log.Printf("Port %d disabled by flag", p)
		}
	}

	// Parse capture mode.
	captureMode, err := ebpf.ParseCaptureMode(*captureModeFlag)
	if err != nil {
		log.Printf("Warning: %v — defaulting to go-only", err)
		captureMode = ebpf.ModeGoOnly
	}

	// Parse management ports for eBPF bypass map.
	var mgmtPorts []uint16
	for _, tok := range strings.Split(*mgmtPortsFlag, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, err := strconv.ParseUint(tok, 10, 16)
		if err != nil {
			log.Printf("Warning: invalid mgmt-port %q, skipping: %v", tok, err)
			continue
		}
		mgmtPorts = append(mgmtPorts, uint16(p))
	}

	// Determine working directory for persistent storage.
	// When run as a systemd service the unit sets WorkingDirectory=/var/lib/webtraffik.
	// For local dev runs we fall back to the current directory.
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}

	// Open (or create) the SQLite event database.
	appDB, err = db.OpenEventDB(workDir)
	if err != nil {
		log.Fatalf("Failed to open event database: %v", err)
	}
	defer appDB.Close()

	// Create the rate-limiter, injecting the portServiceName callback and a
	// metrics-recording onBan callback (metrics cache created below).
	// The onBan closure captures appMetrics by pointer — safe because appMetrics
	// is set before any connection handler can fire.
	appLimiter = ratelimit.New(
		services.PortServiceName,
		func(banType string) {
			if appMetrics != nil {
				appMetrics.RecordBan(banType)
			}
		},
	)
	appLimiter.SetDB(appDB)
	appLimiter.LoadBans()

	// ── eBPF manager ──────────────────────────────────────────────────────────
	// Create and start the eBPF XDP capture manager. On any attach failure
	// (missing CAP_BPF, old kernel, incompatible driver) we fall back to
	// go-only mode transparently — the application continues normally.
	appEBPF = ebpf.New(captureMode, *ebpfIfaceFlag, mgmtPorts, *mgmtAllowFileFlag)
	if err := appEBPF.Start(); err != nil {
		log.Printf("ebpf: WARNING: failed to attach XDP program: %v", err)
		log.Printf("ebpf: falling back to go-only mode")
		appEBPF = ebpf.New(ebpf.ModeGoOnly, "", nil, "")
	} else if captureMode != ebpf.ModeGoOnly {
		log.Printf("ebpf: running in %s mode on interface %q", captureMode, *ebpfIfaceFlag)
	}
	defer appEBPF.Stop()

	// Wire eBPF ban sync into the rate limiter so every Go-triggered ban/unban
	// is immediately reflected in the XDP ban_map.
	appLimiter.SetEBPFManager(appEBPF)

	// SIGHUP handler: reload mgmt allow file without restarting.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP)
		for range sigCh {
			log.Printf("ebpf: SIGHUP received — reloading mgmt allow file")
			if err := appEBPF.ReloadAllowFile(); err != nil {
				log.Printf("ebpf: allow file reload failed: %v", err)
			}
		}
	}()

	// Backfill metrics from events table (idempotent — skipped if table is not empty).
	if err := appDB.BackfillMetrics(services.PortServiceName); err != nil {
		log.Printf("Warning: metrics backfill failed: %v", err)
	}

	// Start the in-memory metrics cache with flush loop.
	appMetrics = metrics.NewCache(appDB, services.PortServiceName)
	defer appMetrics.Close()

	// Seed the in-memory ring buffer from persisted history so new clients
	// get replayed events immediately while the DB query on /ws is also live.
	if history, err := appDB.LoadHistory(historySize); err == nil {
		appHub.mu.Lock()
		appHub.history = history
		appHub.mu.Unlock()
		log.Printf("Loaded %d historical events from DB", len(history))
	} else {
		log.Printf("Warning: could not load history from DB: %v", err)
	}

	// Ensure GeoLite2 DB exists, downloading it if needed.
	dbPath, err := geo.EnsureGeoDB()
	if err != nil {
		log.Fatalf("Failed to obtain GeoLite2 database: %v", err)
	}

	appGeo, err = geo.NewGeoLocator(dbPath, !*disableRgeo)
	if err != nil {
		log.Fatalf("Failed to open GeoLite2 database: %v", err)
	}
	defer appGeo.Close()

	// Discover our public IP and geolocate it.
	selfIP, err = iputil.DiscoverPublicIP()
	if err != nil {
		log.Printf("Warning: could not discover public IP: %v", err)
		selfIP = "unknown"
	} else {
		log.Printf("Public IP: %s", selfIP)
		loc, err2 := appGeo.Lookup(selfIP)
		if err2 == nil {
			selfLat = loc.Lat
			selfLon = loc.Lon
			selfCity = loc.City
			selfCC = loc.CountryCode
			log.Printf("Self location: %s, %s (%.4f, %.4f)", selfCity, selfCC, selfLat, selfLon)
		}
	}

	// ── Start listeners ────────────────────────────────────────────────────
	// In ebpf-only mode the XDP program handles telemetry; no Go listeners
	// are spawned (service emulation / banners are unavailable in this mode).
	if captureMode != ebpf.ModeEBPFOnly {
		// HTTP capture ports.
		for _, port := range capturePorts {
			if disabledPorts[port] {
				continue
			}
			go startCaptureListener(port)
		}

		// TCP service emulation listeners (non-HTTP protocols with banners).
		for _, svc := range services.TCPServices {
			if disabledPorts[svc.Port] {
				continue
			}
			go services.StartTCPServiceListener(svc, appLimiter.IsBanned, handleCapture)
		}

		// UDP service listeners.
		for _, port := range services.UDPServicePorts {
			if disabledPorts[port] {
				continue
			}
			go services.StartUDPServiceListener(port, handleCapture)
		}

		// Special protocol emulators.
		if !disabledPorts[services.MinecraftPort] {
			go services.StartMinecraftListener(appLimiter.IsBanned, handleCapture)
		}
		if !disabledPorts[services.LightningPort] {
			go services.StartLightningListener(appLimiter.IsBanned, handleCapture)
		}
		if !disabledPorts[services.VNCPort] {
			go services.StartVNCListener(appLimiter.IsBanned, handleCapture)
		}
	} else {
		log.Printf("ebpf-only mode: Go listeners not started (service emulation unavailable)")
		// In ebpf-only mode, pump eBPF perf events into the hub pipeline.
		go pumpEBPFEvents()
	}

	// Dashboard server.
	go startDashboardServer()

	log.Println("Dashboard available at http://localhost:8999")

	// Block forever.
	select {}
}

// ── capture ───────────────────────────────────────────────────────────────────

// startCaptureListener binds to the given port, records every incoming HTTP
// request, and returns a realistic HTTP/1.1 response that mimics nginx.
func startCaptureListener(port int) {
	addr := fmt.Sprintf(":%d", port)
	portStr := fmt.Sprintf("%d", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		srcIP := extractIP(r.RemoteAddr)
		// Drop banned IPs immediately — hijack the underlying TCP connection
		// and close it without writing a single byte.
		if appLimiter.IsBanned(srcIP, portStr) {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					conn.Close()
				}
			}
			return
		}
		// Return a convincing nginx-style 200 with a minimal HTML body.
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>")
		// Build a text summary of the HTTP request for client data capture.
		httpSummary := fmt.Sprintf("%s %s %s\nHost: %s\nUser-Agent: %s",
			r.Method, r.URL.RequestURI(), r.Proto, r.Host, r.UserAgent())
		go handleCapture(srcIP, portStr, "tcp", []byte(httpSummary))
	})
	log.Printf("Capture listener on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Capture listener on %s failed: %v", addr, err)
	}
}

// handleCapture is the central event handler. It is called from every listener
// type (HTTP, TCP service, UDP, special protocols).
func handleCapture(srcIP, dstPort, protocol string, clientData []byte) {
	// Rate-limit check: only meaningful for TCP — UDP is stateless.
	if protocol != "udp" && !appLimiter.Record(srcIP, dstPort) {
		return
	}

	var srcLat, srcLon float64
	var srcCity, srcCC string

	loc, err := appGeo.Lookup(srcIP)
	if err == nil {
		srcLat = loc.Lat
		srcLon = loc.Lon
		srcCity = loc.City
		srcCC = loc.CountryCode
	} else {
		log.Printf("Geo lookup failed for %s: %v", srcIP, err)
	}

	ev := event.ConnectionEvent{
		Time:       time.Now().UTC().Format(time.RFC3339),
		SrcIP:      srcIP,
		DstIP:      selfIP,
		DstPort:    dstPort,
		Protocol:   protocol,
		SrcLat:     srcLat,
		SrcLon:     srcLon,
		DstLat:     selfLat,
		DstLon:     selfLon,
		SrcCity:    srcCity,
		DstCity:    selfCity,
		SrcCC:      srcCC,
		DstCC:      selfCC,
		ClientData: hex.EncodeToString(clientData),
	}
	appHub.broadcast(ev)
	appDB.Insert(ev)
	appMetrics.Record(ev)

	evJSON, _ := json.Marshal(ev)
	log.Printf("Connection: %s", string(evJSON))
}

// ── dashboard server ──────────────────────────────────────────────────────────

// startDashboardServer serves the web UI and WebSocket endpoint on :8999.
func startDashboardServer() {
	mux := http.NewServeMux()

	// Serve static frontend — strip the "static/" prefix so / serves index.html.
	mux.Handle("/", http.FileServer(http.FS(staticSubFS())))

	// Self-info endpoint.
	mux.HandleFunc("/api/self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":   selfIP,
			"lat":  selfLat,
			"lon":  selfLon,
			"city": selfCity,
			"cc":   selfCC,
		})
	})

	// History query endpoint.
	// GET /api/history?country=US&ip=1.2&port=22&service=SSH&date_from=2024-01-01T00:00&date_to=2024-12-31T23:59
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := db.HistoryFilter{
			Country:  q.Get("country"),
			IP:       q.Get("ip"),
			Port:     q.Get("port"),
			Service:  q.Get("service"),
			DateFrom: q.Get("date_from"),
			DateTo:   q.Get("date_to"),
		}
		events, err := appDB.QueryHistory(f, services.PortsForService)
		if err != nil {
			http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if events == nil {
			events = []event.ConnectionEvent{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	// Banned IPs endpoint — returns the current active ban list.
	mux.HandleFunc("/api/banned", func(w http.ResponseWriter, r *http.Request) {
		bans := appLimiter.ActiveBans()
		if bans == nil {
			bans = []ratelimit.BanEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bans)
	})

	// Port scanners endpoint — returns IPs currently classified as scanners.
	mux.HandleFunc("/api/scanners", func(w http.ResponseWriter, r *http.Request) {
		scanners := appLimiter.ActiveScanners()
		if scanners == nil {
			scanners = []ratelimit.ScannerEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanners)
	})

	// Manual ban endpoint — POST { "ip": "1.2.3.4", "port": "22" }
	mux.HandleFunc("/api/ban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP   string `json:"ip"`
			Port string `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" || req.Port == "" {
			http.Error(w, "invalid request: ip and port required", http.StatusBadRequest)
			return
		}
		ok := appLimiter.ManualBan(req.IP, req.Port)
		w.Header().Set("Content-Type", "application/json")
		if ok {
			log.Printf("Manual ban: %s on port %s", req.IP, req.Port)
			json.NewEncoder(w).Encode(map[string]string{"status": "banned"})
		} else {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"status": "already_banned"})
		}
	})

	// Manual unban endpoint — POST { "ip": "1.2.3.4", "port": "22" }
	mux.HandleFunc("/api/unban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP   string `json:"ip"`
			Port string `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" || req.Port == "" {
			http.Error(w, "invalid request: ip and port required", http.StatusBadRequest)
			return
		}
		ok := appLimiter.ManualUnban(req.IP, req.Port)
		w.Header().Set("Content-Type", "application/json")
		if ok {
			log.Printf("Manual unban: %s on port %s", req.IP, req.Port)
			json.NewEncoder(w).Encode(map[string]string{"status": "unbanned"})
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"status": "not_banned"})
		}
	})

	// Recent events endpoint — returns the in-memory ring buffer snapshot
	// (includes ephemeral client_data not stored in the DB).
	mux.HandleFunc("/api/recent", func(w http.ResponseWriter, r *http.Request) {
		events := appHub.snapshot()
		if events == nil {
			events = []event.ConnectionEvent{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	// Services list endpoint — returns all known service names for the filter dropdown.
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		type svcEntry struct {
			Name  string `json:"name"`
			Ports []int  `json:"ports"`
		}
		seen := services.AllServiceNames()
		result := make([]svcEntry, 0, len(seen))
		for name, ports := range seen {
			result = append(result, svcEntry{Name: name, Ports: ports})
		}
		// Sort by name for stable output.
		for i := 1; i < len(result); i++ {
			for j := i; j > 0 && result[j].Name < result[j-1].Name; j-- {
				result[j], result[j-1] = result[j-1], result[j]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Traceroute SSE endpoint.
	// GET /api/traceroute?ip=1.2.3.4
	// Streams Server-Sent Events; each event is a JSON-encoded traceroute.Hop.
	// The stream ends with a final "event: done\ndata: {}\n\n" sentinel.
	mux.HandleFunc("/api/traceroute", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			http.Error(w, "ip query parameter required", http.StatusBadRequest)
			return
		}
		// Validate: must be a parseable, non-private IP.
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() ||
			parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
			http.Error(w, "ip must be a public IP address", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if present
		w.WriteHeader(http.StatusOK)

		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		// Build geo callback wrapping the app-level GeoLocator.
		geoFn := func(ipStr string) (lat, lon float64, city, cc string, accuracyKm uint16) {
			loc, err := appGeo.Lookup(ipStr)
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

		// Send a terminal sentinel so the client knows the trace is complete.
		fmt.Fprintf(w, "event: done\ndata: {}\n\n")
		fl.Flush()
	})

	// Metrics endpoints.
	mux.HandleFunc("/api/metrics", appMetrics.HandleMetrics)
	mux.HandleFunc("/metrics", appMetrics.HandleMetricsPrometheus)

	// eBPF stats endpoint.
	mux.HandleFunc("/api/ebpf/stats", appEBPF.StatsHandler())

	// WebSocket endpoint.
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Printf("WebSocket accept error: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		ctx := conn.CloseRead(context.Background())

		// Subscribe FIRST so live events buffer in the channel during replay.
		ch := appHub.subscribe()
		defer appHub.unsubscribe(ch)

		// Determine replay window: ?hours=N (1-24, default 1).
		hours := 1
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n >= 1 && n <= 24 {
				hours = n
			}
		}
		since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)

		// Replay history from DB for the requested time window.
		history, err := appDB.LoadHistorySince(since)
		if err != nil {
			log.Printf("WebSocket history load error: %v", err)
		}
		for _, ev := range history {
			ev.Replay = true
			if err := wsjson.Write(ctx, conn, ev); err != nil {
				return
			}
		}

		// Drain buffered live events then continue streaming.
		for {
			select {
			case ev := <-ch:
				if err := wsjson.Write(ctx, conn, ev); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	})

	log.Println("Dashboard server on :8999 — http://localhost:8999")
	if err := http.ListenAndServe(":8999", mux); err != nil {
		log.Fatalf("Dashboard server failed: %v", err)
	}
}

// pumpEBPFEvents drains appEBPF.EventCh and routes each event into the
// standard handleCapture pipeline. Used in ebpf-only mode where no Go
// listeners are spawned and all connection events come from the XDP perf buffer.
func pumpEBPFEvents() {
	for ev := range appEBPF.EventCh {
		if ev.Dropped {
			// Dropped packets were already blocked at XDP_DROP; skip capture pipeline
			// but we could log them in future if desired.
			continue
		}
		go handleCapture(ev.SrcIP.String(), fmt.Sprintf("%d", ev.DstPort), "tcp", nil)
	}
}
func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
