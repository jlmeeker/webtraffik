package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// ConnectionEvent is sent to the browser over WebSocket
type ConnectionEvent struct {
	Time     string  `json:"time"`
	SrcIP    string  `json:"src_ip"`
	DstIP    string  `json:"dst_ip"`
	DstPort  string  `json:"dst_port"`
	Protocol string  `json:"protocol"` // "tcp" or "udp"
	SrcLat   float64 `json:"src_lat"`
	SrcLon   float64 `json:"src_lon"`
	DstLat   float64 `json:"dst_lat"`
	DstLon   float64 `json:"dst_lon"`
	SrcCity  string  `json:"src_city"`
	DstCity  string  `json:"dst_city"`
	SrcCC    string  `json:"src_cc"`
	DstCC    string  `json:"dst_cc"`
	Replay   bool    `json:"replay,omitempty"` // true when replayed from history
}

const historySize = 1000

// hub manages WebSocket subscribers and a rolling history buffer
type hub struct {
	mu          sync.Mutex
	subscribers map[chan ConnectionEvent]struct{}
	history     []ConnectionEvent // ring buffer, capped at historySize
}

func newHub() *hub {
	return &hub{
		subscribers: make(map[chan ConnectionEvent]struct{}),
		history:     make([]ConnectionEvent, 0, historySize),
	}
}

func (h *hub) subscribe() chan ConnectionEvent {
	ch := make(chan ConnectionEvent, 256)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan ConnectionEvent) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
}

// snapshot returns a copy of the current history slice, oldest-first.
func (h *hub) snapshot() []ConnectionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]ConnectionEvent, len(h.history))
	copy(out, h.history)
	return out
}

func (h *hub) broadcast(ev ConnectionEvent) {
	h.mu.Lock()
	// Append to history, evict oldest when full
	if len(h.history) >= historySize {
		h.history = append(h.history[1:], ev)
	} else {
		h.history = append(h.history, ev)
	}
	// Snapshot subscriber channels under lock, then release before sending
	subs := make([]chan ConnectionEvent, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	// Fan-out without holding the lock — subscribe/unsubscribe are not blocked
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

var (
	appHub   = newHub()
	appDB    *eventDB
	geo      *GeoLocator
	selfIP   string
	selfLat  float64
	selfLon  float64
	selfCity string
	selfCC   string
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

func main() {
	log.Println("webTraffik starting...")

	// Parse CLI flags
	disablePortsFlag := flag.String("disable-ports", "",
		"Comma-separated list of ports to skip binding (e.g. 22,80,443). "+
			"These ports will not be listened on. Update your firewall rules accordingly.")
	flag.Parse()

	// Build a set of disabled ports from the flag value
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

	// Determine working directory for persistent storage.
	// When run as a systemd service the unit sets WorkingDirectory=/var/lib/webtraffik.
	// For local dev runs we fall back to the current directory.
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}

	// Open (or create) the SQLite event database.
	appDB, err = openEventDB(workDir)
	if err != nil {
		log.Fatalf("Failed to open event database: %v", err)
	}
	defer appDB.close()

	// Wire the rate-limiter to the DB so bans are persisted and survive restarts.
	appLimiter.SetDB(appDB)
	appLimiter.LoadBans(appDB)

	// Seed the in-memory ring buffer from persisted history so new clients
	// get replayed events immediately while the DB query on /ws is also live.
	if history, err := appDB.loadHistory(historySize); err == nil {
		appHub.mu.Lock()
		appHub.history = history
		appHub.mu.Unlock()
		log.Printf("Loaded %d historical events from DB", len(history))
	} else {
		log.Printf("Warning: could not load history from DB: %v", err)
	}

	// Ensure GeoLite2 DB exists
	dbPath, err := ensureGeoDB()
	if err != nil {
		log.Fatalf("Failed to obtain GeoLite2 database: %v", err)
	}

	geo, err = NewGeoLocator(dbPath)
	if err != nil {
		log.Fatalf("Failed to open GeoLite2 database: %v", err)
	}
	defer geo.Close()

	// Discover our public IP and geolocate it
	selfIP, err = discoverPublicIP()
	if err != nil {
		log.Printf("Warning: could not discover public IP: %v", err)
		selfIP = "unknown"
	} else {
		log.Printf("Public IP: %s", selfIP)
		loc, err2 := geo.Lookup(selfIP)
		if err2 == nil {
			selfLat = loc.Lat
			selfLon = loc.Lon
			selfCity = loc.City
			selfCC = loc.CountryCode
			log.Printf("Self location: %s, %s (%.4f, %.4f)", selfCity, selfCC, selfLat, selfLon)
		}
	}

	// Start capture listeners on all common HTTP ports
	for _, port := range capturePorts {
		if disabledPorts[port] {
			continue
		}
		go startCaptureListener(port)
	}

	// Start TCP service emulation listeners (non-HTTP protocols)
	for _, svc := range tcpServices {
		if disabledPorts[svc.Port] {
			continue
		}
		go startTCPServiceListener(svc)
	}

	// Start UDP service listeners
	for _, port := range udpServicePorts {
		if disabledPorts[port] {
			continue
		}
		go startUDPServiceListener(port)
	}

	// Start Minecraft Java Edition server-list-ping emulator
	if !disabledPorts[minecraftPort] {
		go startMinecraftListener()
	}

	// Start dashboard server on 8999
	go startDashboardServer()

	log.Println("Dashboard available at http://localhost:8999")

	// Block forever
	select {}
}

// startCaptureListener binds to the given port, records every incoming HTTP
// request, and returns a realistic HTTP/1.1 response that mimics a common
// web server (nginx).
func startCaptureListener(port int) {
	addr := fmt.Sprintf(":%d", port)
	portStr := fmt.Sprintf("%d", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		srcIP := extractIP(r.RemoteAddr)
		// Return a convincing nginx-style 200 with a minimal HTML body.
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>")
		go handleCapture(srcIP, portStr, "tcp")
	})
	log.Printf("Capture listener on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Capture listener on %s failed: %v", addr, err)
	}
}

func handleCapture(srcIP, dstPort, protocol string) {
	// Rate-limit check: only meaningful for TCP — UDP is stateless/fire-and-forget
	// so there is nothing to terminate and no cost to absorb per-packet.
	if protocol != "udp" && !appLimiter.Record(srcIP, dstPort) {
		return
	}

	var srcLat, srcLon float64
	var srcCity, srcCC string

	loc, err := geo.Lookup(srcIP)
	if err == nil {
		srcLat = loc.Lat
		srcLon = loc.Lon
		srcCity = loc.City
		srcCC = loc.CountryCode
	} else {
		log.Printf("Geo lookup failed for %s: %v", srcIP, err)
	}

	ev := ConnectionEvent{
		Time:     time.Now().UTC().Format(time.RFC3339),
		SrcIP:    srcIP,
		DstIP:    selfIP,
		DstPort:  dstPort,
		Protocol: protocol,
		SrcLat:   srcLat,
		SrcLon:   srcLon,
		DstLat:   selfLat,
		DstLon:   selfLon,
		SrcCity:  srcCity,
		DstCity:  selfCity,
		SrcCC:    srcCC,
		DstCC:    selfCC,
	}
	appHub.broadcast(ev)
	appDB.insert(ev)

	evJSON, _ := json.Marshal(ev)
	log.Printf("Connection: %s", string(evJSON))
}

// startDashboardServer serves the web UI and WebSocket endpoint on :8999
func startDashboardServer() {
	mux := http.NewServeMux()

	// Serve static frontend — strip the "static/" prefix so / serves index.html
	stripped, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("Failed to sub static fs: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(stripped)))

	// Self-info endpoint
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

	// History query endpoint — GET /api/history?country=US&ip=1.2&port=22&service=SSH&date_from=2024-01-01T00:00&date_to=2024-12-31T23:59
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := HistoryFilter{
			Country:  q.Get("country"),
			IP:       q.Get("ip"),
			Port:     q.Get("port"),
			Service:  q.Get("service"),
			DateFrom: q.Get("date_from"),
			DateTo:   q.Get("date_to"),
		}
		events, err := appDB.queryHistory(f)
		if err != nil {
			http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if events == nil {
			events = []ConnectionEvent{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	// Banned IPs endpoint — returns the current active ban list
	mux.HandleFunc("/api/banned", func(w http.ResponseWriter, r *http.Request) {
		bans := appLimiter.ActiveBans()
		if bans == nil {
			bans = []BanEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bans)
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

	// Services list endpoint — returns all known service names for the filter dropdown
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		type svcEntry struct {
			Name  string `json:"name"`
			Ports []int  `json:"ports"`
		}
		// tcpServiceNames is now the single canonical source for all port→name
		// mappings (TCP services, UDP ports, HTTP capture ports, Minecraft).
		seen := map[string][]int{}
		for port, name := range tcpServiceNames {
			seen[name] = append(seen[name], port)
		}

		var result []svcEntry
		for name, ports := range seen {
			result = append(result, svcEntry{Name: name, Ports: ports})
		}
		// Sort by name for stable output
		for i := 1; i < len(result); i++ {
			for j := i; j > 0 && result[j].Name < result[j-1].Name; j-- {
				result[j], result[j-1] = result[j-1], result[j]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// WebSocket endpoint
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
		// The 256-deep channel absorbs bursts while we send history.
		ch := appHub.subscribe()
		defer appHub.unsubscribe(ch)

		// Determine replay window: ?hours=N (1-24, default 1)
		hours := 1
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n >= 1 && n <= 24 {
				hours = n
			}
		}
		since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format(time.RFC3339)

		// Replay history from DB for the requested time window.
		history, err := appDB.loadHistorySince(since)
		if err != nil {
			log.Printf("WebSocket history load error: %v", err)
		}
		for _, ev := range history {
			ev.Replay = true
			if err := wsjson.Write(ctx, conn, ev); err != nil {
				return
			}
		}

		// Drain any live events that arrived while replaying history,
		// then continue streaming live events.
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

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
