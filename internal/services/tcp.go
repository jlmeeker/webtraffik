package services

import (
	"fmt"
	"log"
	"net"
	"time"
)

// CaptureFunc is the callback signature used to report a connection event.
// srcIP is the source IP, dstPort is the destination port string (e.g. "22"),
// protocol is "tcp" or "udp", and clientData is raw bytes read from the client.
type CaptureFunc func(srcIP, dstPort, protocol string, clientData []byte)

// IsBannedFunc checks whether a given IP+port is currently banned.
type IsBannedFunc func(ip, port string) bool

// TCPServices is the list of non-HTTP TCP services webTraffik emulates.
// Each service sends a convincing initial banner then closes the connection.
var TCPServices = tcpServices

// UDPServicePorts are the UDP ports webTraffik captures.
// We bind, read one datagram to get the source address, fire the event, and discard the payload.
var UDPServicePorts = udpServicePorts

// StartTCPServiceListener accepts TCP connections on the given port,
// fires a capture event, writes the service banner, and closes.
func StartTCPServiceListener(svc serviceEntry, isBanned IsBannedFunc, capture CaptureFunc) {
	addr := fmt.Sprintf(":%d", svc.Port)
	portStr := fmt.Sprintf("%d", svc.Port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("TCP service listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("TCP service listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("TCP service accept on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			srcIP := extractConnIP(c.RemoteAddr())
			// Drop banned IPs before sending the banner.
			if isBanned(srcIP, portStr) {
				return
			}
			banner := svc.Banner()
			if len(banner) > 0 {
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c.Write(banner) //nolint:errcheck
			}
			// Read up to 256 bytes of client data after the banner.
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			clientBuf := make([]byte, 256)
			n, _ := c.Read(clientBuf)
			go capture(srcIP, portStr, "tcp", clientBuf[:n])
		}(conn)
	}
}

// StartUDPServiceListener binds to a UDP port and fires a capture event for
// each datagram received. No response is sent.
func StartUDPServiceListener(port int, capture CaptureFunc) {
	addr := fmt.Sprintf(":%d", port)
	portStr := fmt.Sprintf("%d", port)

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("UDP service listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("UDP service listener on %s", addr)

	buf := make([]byte, 4096)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		srcIP := extractConnIP(src)
		// Copy the datagram payload (up to 256 bytes) before the next ReadFrom
		// overwrites the buffer.
		limit := n
		if limit > 256 {
			limit = 256
		}
		clientData := make([]byte, limit)
		copy(clientData, buf[:limit])
		go capture(srcIP, portStr, "udp", clientData)
	}
}

// extractConnIP extracts the host from a net.Addr.
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
