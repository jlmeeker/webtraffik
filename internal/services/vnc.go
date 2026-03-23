package services

import (
	"io"
	"log"
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

// StartVNCListener binds to VNCPort and emulates an RFB version handshake
// with an optional tarpit for repeat connections.
func StartVNCListener(isBanned IsBannedFunc, capture CaptureFunc) {
	portStr := "5900"
	addr := ":5900"

	// Periodically prune stale entries from the seen-IP map.
	go func() {
		for range time.Tick(5 * time.Minute) {
			vncSeenMu.Lock()
			cutoff := time.Now().Add(-vncTarpitWindow)
			for ip, t := range vncSeenIPs {
				if t.Before(cutoff) {
					delete(vncSeenIPs, ip)
				}
			}
			vncSeenMu.Unlock()
		}
	}()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("VNC listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("VNC listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("VNC accept on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			srcIP := extractConnIP(c.RemoteAddr())
			if isBanned(srcIP, portStr) {
				return
			}
			repeat := vncIsRepeat(srcIP)
			clientData := handleVNCConn(c, repeat)
			go capture(srcIP, portStr, "tcp", clientData)
		}(conn)
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
