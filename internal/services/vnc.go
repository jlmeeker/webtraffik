package services

import (
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ── VNC (RFB) version exchange with tarpit ────────────────────────────────────
//
// First connection from an IP:
//  1. Server → Client: "RFB 003.008\n"   (protocol version)
//  2. Client → Server: "RFB 003.0xx\n"   (client version — captured)
//  3. Connection closed silently
//
// Repeat connections from the same IP within vncTarpitWindow:
//  Steps 1–2 as above (still captured), then the connection is held open
//  for a random 10–30 second delay before closing.

// VNCPort is the default VNC (RFB) port.
const VNCPort = 5900

const vncTarpitWindow = 60 * time.Second
const vncTarpitMin = 10 * time.Second
const vncTarpitMax = 30 * time.Second

var (
	vncSeenMu  sync.Mutex
	vncSeenIPs = make(map[string]time.Time)
)

func vncIsRepeat(ip string) bool {
	vncSeenMu.Lock()
	defer vncSeenMu.Unlock()
	last, ok := vncSeenIPs[ip]
	now := time.Now()
	vncSeenIPs[ip] = now
	return ok && now.Sub(last) < vncTarpitWindow
}

// pruneVNCSeen periodically drops stale entries from the seen-IP map until
// ctx is cancelled.
func pruneVNCSeen(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			vncSeenMu.Lock()
			cutoff := time.Now().Add(-vncTarpitWindow)
			for ip, seen := range vncSeenIPs {
				if seen.Before(cutoff) {
					delete(vncSeenIPs, ip)
				}
			}
			vncSeenMu.Unlock()
		}
	}
}

func handleVNCConn(c net.Conn, tarpit bool) []byte {
	c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return nil
	}

	clientVersion := make([]byte, 12)
	if _, err := io.ReadFull(c, clientVersion); err != nil {
		return nil
	}

	if tarpit {
		hold := vncTarpitMin + time.Duration(rand.Int63n(int64(vncTarpitMax-vncTarpitMin)))
		c.SetDeadline(time.Now().Add(hold + 5*time.Second))
		time.Sleep(hold)
	}

	return clientVersion
}
