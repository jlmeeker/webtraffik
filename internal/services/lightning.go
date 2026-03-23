package services

import (
	"io"
	"log"
	"net"
	"time"
)

// ── Lightning Network P2P (BOLT #8) emulator ─────────────────────────────────
//
// Protocol reference: BOLT #8 — Encrypted and Authenticated Transport
//
// The Noise_XK handshake has three acts:
//  1. Initiator → Responder: Act One  (50 bytes)
//  2. Responder → Initiator: Act Two  (50 bytes)
//  3. Initiator → Responder: Act Three (66 bytes)
//
// We read Act One from the client, then send a fake Act Two response.

// LightningPort is the default Lightning Network peer port.
const LightningPort = 9735

// StartLightningListener binds to LightningPort and emulates the BOLT #8
// Noise_XK handshake: reads the client's 50-byte Act One, then sends
// a 50-byte Act Two response.
func StartLightningListener(isBanned IsBannedFunc, capture CaptureFunc) {
	portStr := "9735"
	addr := ":9735"

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Lightning listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("Lightning listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Lightning accept on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			srcIP := extractConnIP(c.RemoteAddr())
			if isBanned(srcIP, portStr) {
				return
			}
			clientData := handleLightningConn(c)
			go capture(srcIP, portStr, "tcp", clientData)
		}(conn)
	}
}

// handleLightningConn processes a single Lightning Network connection:
// reads the 50-byte Act One from the initiator, then sends a 50-byte
// Act Two response, then closes. Returns the Act One bytes as client data.
func handleLightningConn(c net.Conn) []byte {
	c.SetDeadline(time.Now().Add(5 * time.Second))

	actOne := make([]byte, 50)
	if _, err := io.ReadFull(c, actOne); err != nil {
		return nil
	}

	// Send Act Two: 1 byte version + 33 bytes ephemeral pubkey + 16 bytes tag = 50 bytes.
	// Deterministic but realistic-looking bytes (no real Noise_XK crypto).
	actTwo := make([]byte, 50)
	actTwo[0] = 0x00 // version byte (must be 0)
	for i := 1; i < 50; i++ {
		actTwo[i] = byte((i * 37) ^ 0xAB)
	}
	c.Write(actTwo) //nolint:errcheck
	return actOne
}
