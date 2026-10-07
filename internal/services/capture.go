package services

import (
	"context"
	"net"
)

// Capture is one observed connection attempt handed to the application.
type Capture struct {
	SrcIP    string
	DstPort  string
	Protocol string            // "tcp" or "udp"
	Data     []byte            // raw bytes sent by the client (capped by the caller)
	Detail   string            // one-line human-readable summary
	Tags     []string          // classifier labels
	Meta     map[string]string // structured extras (credentials, fingerprints…)
	Kind     string            // optional: set by non-listener sources ("observed" for XDP)
}

// CaptureFunc reports a Capture. It must not block: the application enqueues
// the event and returns immediately.
type CaptureFunc func(Capture)

// IsBannedFunc checks whether a given IP+port is currently banned.
type IsBannedFunc func(ip, port string) bool

// Result is what a ConnHandler learned from one connection.
type Result struct {
	Data   []byte
	Detail string
	Tags   []string
	Meta   map[string]string
}

// ConnHandler speaks one emulated protocol on an accepted connection. The
// connection already has an overall deadline and is closed by the caller.
type ConnHandler func(ctx context.Context, c net.Conn, srcIP string) Result

// clip returns at most n bytes of b.
func clip(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func extractConnIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}
