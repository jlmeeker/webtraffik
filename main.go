package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// ConnectionEvent is sent to the browser over WebSocket
type ConnectionEvent struct {
	Time    string  `json:"time"`
	SrcIP   string  `json:"src_ip"`
	DstIP   string  `json:"dst_ip"`
	DstPort string  `json:"dst_port"`
	SrcLat  float64 `json:"src_lat"`
	SrcLon  float64 `json:"src_lon"`
	DstLat  float64 `json:"dst_lat"`
	DstLon  float64 `json:"dst_lon"`
	SrcCity string  `json:"src_city"`
	DstCity string  `json:"dst_city"`
	SrcCC   string  `json:"src_cc"`
	DstCC   string  `json:"dst_cc"`
	Replay  bool    `json:"replay,omitempty"` // true when replayed from history
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
	ch := make(chan ConnectionEvent, 32)
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
	defer h.mu.Unlock()

	// Append to history, evict oldest when full
	if len(h.history) >= historySize {
		h.history = append(h.history[1:], ev)
	} else {
		h.history = append(h.history, ev)
	}

	for ch := range h.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
}

var (
	appHub   = newHub()
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
		go startCaptureListener(port)
	}

	// Start dashboard server on 8999
	go startDashboardServer()

	log.Println("Dashboard available at http://localhost:8999")

	// Block forever
	select {}
}

// startCaptureListener binds to the given port, returns empty 200 for all
// requests and fires a ConnectionEvent tagged with that port number.
func startCaptureListener(port int) {
	addr := fmt.Sprintf(":%d", port)
	portStr := fmt.Sprintf("%d", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		srcIP := extractIP(r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		go handleCapture(srcIP, portStr)
	})
	log.Printf("Capture listener on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("Capture listener on %s failed: %v", addr, err)
	}
}

func handleCapture(srcIP, dstPort string) {
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
		Time:    time.Now().UTC().Format(time.RFC3339),
		SrcIP:   srcIP,
		DstIP:   selfIP,
		DstPort: dstPort,
		SrcLat:  srcLat,
		SrcLon:  srcLon,
		DstLat:  selfLat,
		DstLon:  selfLon,
		SrcCity: srcCity,
		DstCity: selfCity,
		SrcCC:   srcCC,
		DstCC:   selfCC,
	}
	appHub.broadcast(ev)

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

		// Replay history to the new client before subscribing to live events
		for _, ev := range appHub.snapshot() {
			ev.Replay = true
			if err := wsjson.Write(ctx, conn, ev); err != nil {
				return
			}
		}

		ch := appHub.subscribe()
		defer appHub.unsubscribe(ch)

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
