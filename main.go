package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
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
	SrcLat  float64 `json:"src_lat"`
	SrcLon  float64 `json:"src_lon"`
	DstLat  float64 `json:"dst_lat"`
	DstLon  float64 `json:"dst_lon"`
	SrcCity string  `json:"src_city"`
	DstCity string  `json:"dst_city"`
	SrcCC   string  `json:"src_cc"`
	DstCC   string  `json:"dst_cc"`
}

// hub manages WebSocket subscribers
type hub struct {
	mu          sync.Mutex
	subscribers map[chan ConnectionEvent]struct{}
}

func newHub() *hub {
	return &hub{subscribers: make(map[chan ConnectionEvent]struct{})}
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

func (h *hub) broadcast(ev ConnectionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
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

	// Start port 80 HTTP capture listener
	go startCaptureServer()

	// Start dashboard server on 8999
	go startDashboardServer()

	// Open browser
	time.Sleep(500 * time.Millisecond)
	openBrowser("http://localhost:8999")

	// Block forever
	select {}
}

// startCaptureServer listens on port 80, returns empty 200 for all requests
// and fires a ConnectionEvent for each one.
func startCaptureServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		srcIP := extractIP(r.RemoteAddr)
		w.WriteHeader(http.StatusOK)

		go handleCapture(srcIP)
	})
	log.Println("Capture listener on :80")
	if err := http.ListenAndServe(":80", mux); err != nil {
		log.Fatalf("Port 80 listener failed: %v", err)
	}
}

func handleCapture(srcIP string) {
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

	// Serve static frontend
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))

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

		ch := appHub.subscribe()
		defer appHub.unsubscribe(ch)

		ctx := conn.CloseRead(context.Background())
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

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default:
		fmt.Printf("Open browser manually: %s\n", url)
		return
	}
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		log.Printf("Could not open browser: %v", err)
	}
}
