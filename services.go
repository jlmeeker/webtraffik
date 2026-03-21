package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// tcpServiceNames maps well-known TCP service ports to a display name.
// This is the canonical source used by portServiceName() and portsForService().
var tcpServiceNames = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	18789: "OpenClaw",
}

// serviceEntry describes a TCP service the app impersonates.
type serviceEntry struct {
	Port   int
	Banner func() []byte // returns the bytes to write immediately after accept
}

// tcpServices is the list of non-HTTP TCP services webTraffik emulates.
// Each service sends a convincing initial banner then closes the connection.
var tcpServices = []serviceEntry{
	{
		Port: 21, // FTP
		Banner: func() []byte {
			return []byte("220 FTP Server ready.\r\n")
		},
	},
	{
		Port: 22, // SSH
		Banner: func() []byte {
			return []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
		},
	},
	{
		Port: 23, // Telnet
		Banner: func() []byte {
			// IAC DO TERMINAL-TYPE, IAC DO NAWS — minimal telnet negotiation
			return []byte("\xff\xfd\x18\xff\xfd\x1f\r\nLogin: ")
		},
	},
	{
		Port: 25, // SMTP
		Banner: func() []byte {
			return []byte(fmt.Sprintf("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"))
		},
	},
	{
		Port: 110, // POP3
		Banner: func() []byte {
			return []byte("+OK POP3 server ready\r\n")
		},
	},
	{
		Port: 143, // IMAP
		Banner: func() []byte {
			return []byte("* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot ready.\r\n")
		},
	},
	{
		Port: 443, // HTTPS — TLS ClientHello arrives; we can't actually handshake,
		// but returning a TLS alert (handshake_failure) is the realistic response.
		Banner: func() []byte {
			// TLS 1.0 alert: fatal, handshake_failure (0x28)
			// Record: content_type=21 (alert), version=0x0301, length=0x0002, level=2 (fatal), desc=40 (handshake_failure)
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 445, // SMB
		Banner: func() []byte {
			// Minimal NetBIOS Session Service / SMB2 NEGOTIATE response indicator.
			// Just enough to fingerprint as Windows SMB.
			// SMB2 negotiate response header magic + error STATUS_NOT_SUPPORTED
			return []byte{
				0x00, 0x00, 0x00, 0x54, // NetBIOS session header (len=84)
				0xFE, 'S', 'M', 'B', // SMB2 magic
				0x40, 0x00, // StructureSize
				0x00, 0x00, // CreditCharge
				0x00, 0x00, 0x00, 0xC0, // Status: STATUS_NOT_SUPPORTED
				0x00, 0x00, // Command: NEGOTIATE
				0x00, 0x00, // Credits
				0x00, 0x00, 0x00, 0x00, // Flags
				0x00, 0x00, 0x00, 0x00, // NextCommand
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId
				0x00, 0x00, 0x00, 0x00, // Reserved
				0x00, 0x00, 0x00, 0x00, // TreeId
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (part 1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (part 2)
			}
		},
	},
	{
		Port: 1433, // MSSQL
		Banner: func() []byte {
			// TDS pre-login response: server version 15.00.2000, encryption not supported
			return []byte{
				0x04,       // type: TABULAR_RESULT
				0x01,       // status: EOM
				0x00, 0x25, // length: 37
				0x00, 0x00, // SPID
				0x01, // PacketID
				0x00, // Window
				// Pre-login option: VERSION token=0x00, offset=0x0015, length=6
				0x00, 0x00, 0x15, 0x00, 0x06,
				// Pre-login option: ENCRYPTION token=0x01, offset=0x001b, length=1
				0x01, 0x00, 0x1b, 0x00, 0x01,
				// terminator
				0xff,
				// VERSION: 15.00.2000.5 -> 0x0F 0x00 0x07 0xD0 0x00 0x05
				0x0f, 0x00, 0x07, 0xd0, 0x00, 0x05,
				// ENCRYPTION: 0x02 = ENCRYPT_NOT_SUP
				0x02,
			}
		},
	},
	{
		Port: 3306, // MySQL
		Banner: func() []byte {
			// MySQL 8 handshake packet (Protocol 10)
			serverVersion := "8.0.35\x00"
			// Minimal handshake v10
			pkt := []byte{
				0x0a, // protocol version 10
			}
			pkt = append(pkt, []byte(serverVersion)...)
			pkt = append(pkt,
				0x01, 0x00, 0x00, 0x00, // connection id = 1
				// auth-plugin-data-part-1 (8 bytes)
				0x52, 0x59, 0x41, 0x4e, 0x44, 0x4f, 0x4d, 0x58,
				0x00,       // filler
				0x02, 0xff, // capability flags (lower 2 bytes)
				0x21,       // charset: utf8mb4
				0x02, 0x00, // status flags: SERVER_STATUS_AUTOCOMMIT
				0x7f, 0xff, // capability flags (upper 2 bytes)
				0x15, // auth plugin data length = 21
				// reserved (10 bytes)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// auth-plugin-data-part-2 (13 bytes)
				0x53, 0x54, 0x52, 0x4f, 0x4e, 0x47, 0x50, 0x41, 0x53, 0x53, 0x57, 0x44, 0x00,
				// auth plugin name
				0x63, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68, 0x61, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
			)
			// Wrap in MySQL packet framing: 3-byte length (LE) + 1-byte sequence
			length := len(pkt)
			framed := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0x00}
			return append(framed, pkt...)
		},
	},
	{
		Port: 3389, // RDP
		Banner: func() []byte {
			// X.224 Connection Confirm PDU — standard RDP negotiation response
			// indicating RDP_NEG_RSP with PROTOCOL_RDP (no enhanced security)
			return []byte{
				0x03, 0x00, // TPKT version=3
				0x00, 0x13, // TPKT length=19
				0x0e,       // X.224 header length
				0xd0,       // X.224 type: CC (Connection Confirm)
				0x00, 0x00, // DST-REF
				0x00, 0x00, // SRC-REF
				0x00, // Class/Options
				// RDP_NEG_RSP
				0x02,       // type: RDP_NEG_RSP
				0x00,       // flags
				0x08, 0x00, // length=8
				0x00, 0x00, 0x00, 0x00, // selected protocol: PROTOCOL_RDP
			}
		},
	},
	{
		Port: 5432, // PostgreSQL
		Banner: func() []byte {
			// PostgreSQL sends nothing until the client sends a startup message.
			// A realistic response to an unrecognized/short startup is an error.
			// ErrorResponse: 'E' + int32(len) + fields
			msg := "EFATAL\x00VFATAL\x00C28000\x00Mno pg_hba.conf entry for host\x00\x00"
			length := 4 + len(msg) // int32 includes itself
			return []byte{
				'E',
				byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
			}
		},
	},
	{
		Port: 6379, // Redis
		Banner: func() []byte {
			// Redis inline error: not accepting connections (AUTH required or protected mode)
			return []byte("-DENIED Redis is running in protected mode\r\n")
		},
	},
	{
		Port: 27017, // MongoDB
		Banner: func() []byte {
			// MongoDB wire protocol OP_MSG reply indicating authentication required.
			// Minimal OP_REPLY (opcode 1) with a BSON document: {ok:0, errmsg:"Authentication required"}
			// BSON doc: {ok: 0.0 (double), errmsg: "Authentication required", code: 13}
			bsonDoc := []byte{
				// doc length (LE int32) — will be set after building
				0x00, 0x00, 0x00, 0x00,
				// ok: 0.0 (double, 8 bytes)
				0x01, 'o', 'k', 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// errmsg: "Authentication required"
				0x02, 'e', 'r', 'r', 'm', 's', 'g', 0x00,
				0x17, 0x00, 0x00, 0x00, // string length incl. null
				'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'r', 'e', 'q', 'u', 'i', 'r', 'e', 'd', 0x00,
				// code: 13 (int32)
				0x10, 'c', 'o', 'd', 'e', 0x00,
				0x0d, 0x00, 0x00, 0x00,
				// end of doc
				0x00,
			}
			docLen := len(bsonDoc)
			bsonDoc[0] = byte(docLen)
			bsonDoc[1] = byte(docLen >> 8)
			bsonDoc[2] = byte(docLen >> 16)
			bsonDoc[3] = byte(docLen >> 24)

			// MsgHeader: messageLength(int32) + requestID(int32) + responseTo(int32) + opCode(int32)
			// OP_REPLY = 1
			msgLen := 16 + 4 + 4 + 4 + 4 + len(bsonDoc) // header + flags + cursorID + startingFrom + numberReturned + doc
			hdr := []byte{
				byte(msgLen), byte(msgLen >> 8), byte(msgLen >> 16), byte(msgLen >> 24), // messageLength
				0x01, 0x00, 0x00, 0x00, // requestID
				0x00, 0x00, 0x00, 0x00, // responseTo
				0x01, 0x00, 0x00, 0x00, // opCode OP_REPLY
				0x02, 0x00, 0x00, 0x00, // responseFlags: QueryFailure bit
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cursorID
				0x00, 0x00, 0x00, 0x00, // startingFrom
				0x01, 0x00, 0x00, 0x00, // numberReturned
			}
			return append(hdr, bsonDoc...)
		},
	},
	{
		Port: 5900, // VNC
		Banner: func() []byte {
			// RFB (Remote Framebuffer) protocol version handshake.
			// Server announces highest supported version; most VNC servers send 3.8.
			return []byte("RFB 003.008\n")
		},
	},
	{
		Port: 8443, // HTTPS alt
		Banner: func() []byte {
			// Same TLS handshake_failure alert as port 443.
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 9200, // Elasticsearch
		Banner: func() []byte {
			// Elasticsearch returns a JSON body on GET /. Mimic a 7.17.x node
			// with security enabled (the most common config scanners encounter).
			return []byte(`HTTP/1.1 200 OK
Content-Type: application/json; charset=UTF-8

{
  "name" : "node-1",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "xQ2k9h_lRleh4TnOhK4LJw",
  "version" : {
    "number" : "7.17.16",
    "build_flavor" : "default",
    "build_type" : "deb",
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
`)
		},
	},
	{
		Port: 11211, // Memcached
		Banner: func() []byte {
			// Memcached text protocol error response. Scanners typically send
			// "stats\r\n" or "version\r\n"; reply with an error to fingerprint
			// as a real memcached instance while giving nothing away.
			return []byte("ERROR\r\n")
		},
	},
	{
		Port: 18789, // OpenClaw Gateway
		Banner: func() []byte {
			// OpenClaw is a personal AI assistant whose Gateway listens on
			// port 18789 as an HTTP/WebSocket control plane. A non-WebSocket
			// request receives an HTTP 426 Upgrade Required — the standard
			// response a real OpenClaw Gateway returns to plain HTTP clients.
			return []byte("HTTP/1.1 426 Upgrade Required\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Content-Type: text/plain\r\n" +
				"Content-Length: 25\r\n" +
				"\r\n" +
				"WebSocket upgrade required")
		},
	},
}

// udpServicePorts are the UDP ports webTraffik captures.
// We bind, read one datagram to get the source address, fire the event, and discard the payload.
var udpServicePorts = []int{
	53,   // DNS
	123,  // NTP
	161,  // SNMP
	1900, // SSDP/UPnP
	5060, // SIP
}

// minecraftPort is the default Minecraft Java Edition server port.
const minecraftPort = 25565

// startTCPServiceListener accepts one TCP connection at a time on the given
// port, fires a capture event, writes the service banner, and closes.
func startTCPServiceListener(svc serviceEntry) {
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
			go handleCapture(srcIP, portStr, "tcp")
			banner := svc.Banner()
			if len(banner) > 0 {
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c.Write(banner) //nolint:errcheck
			}
		}(conn)
	}
}

// startUDPServiceListener binds to a UDP port and fires a capture event for
// each datagram received. No response is sent.
func startUDPServiceListener(port int) {
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
		_, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		srcIP := extractConnIP(src)
		go handleCapture(srcIP, portStr, "udp")
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

// ── Minecraft Java Edition server-list-ping emulator ─────────────────────────
//
// Protocol reference: https://wiki.vg/Server_List_Ping
//
// Flow:
//  1. Client → Handshake packet  (ID 0x00, next_state=1)
//  2. Client → Status Request    (ID 0x00, empty payload)
//  3. Server → Status Response   (ID 0x00, JSON payload)
//  4. Client → Ping Request      (ID 0x01, payload int64)
//  5. Server → Pong Response     (ID 0x01, echo same int64)  [optional]
//
// All packets are framed as: VarInt(length) ++ VarInt(packet_id) ++ payload.

// mcReadVarInt reads a Minecraft VarInt from the connection.
func mcReadVarInt(r io.Reader) (int32, error) {
	var result int32
	var shift uint
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= int32(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
		if shift >= 35 {
			return 0, fmt.Errorf("VarInt too large")
		}
	}
}

// mcWriteVarInt encodes a VarInt into a byte slice.
func mcWriteVarInt(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

// mcWriteString encodes a Minecraft protocol String (VarInt length-prefixed UTF-8).
func mcWriteString(s string) []byte {
	b := []byte(s)
	return append(mcWriteVarInt(int32(len(b))), b...)
}

// mcPacket wraps payload bytes into a framed Minecraft packet:
// VarInt(packetID + payload length) ++ VarInt(packetID) ++ payload.
func mcPacket(packetID int32, payload []byte) []byte {
	idBytes := mcWriteVarInt(packetID)
	body := append(idBytes, payload...)
	return append(mcWriteVarInt(int32(len(body))), body...)
}

// mcStatusJSON builds the JSON status response that Minecraft clients display
// in the server browser.
func mcStatusJSON() string {
	type chatText struct {
		Text string `json:"text"`
	}
	type playerSample struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	type players struct {
		Max    int            `json:"max"`
		Online int            `json:"online"`
		Sample []playerSample `json:"sample"`
	}
	type version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	}
	type status struct {
		Version     version  `json:"version"`
		Players     players  `json:"players"`
		Description chatText `json:"description"`
	}

	s := status{
		Version:     version{Name: "1.20.4", Protocol: 765},
		Players:     players{Max: 20, Online: 3, Sample: []playerSample{}},
		Description: chatText{Text: "A Minecraft Server"},
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// handleMinecraftConn processes a single Minecraft client connection:
// reads the handshake + status request, sends a status response, optionally
// echoes the ping, then closes.
func handleMinecraftConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// ── Packet 1: Handshake ────────────────────────────────────────────────
	// Read framing length
	pktLen, err := mcReadVarInt(c)
	if err != nil || pktLen <= 0 || pktLen > 512 {
		return
	}
	pktData := make([]byte, pktLen)
	if _, err := io.ReadFull(c, pktData); err != nil {
		return
	}
	// We don't need to parse the handshake contents; just verify packet ID = 0x00.
	if len(pktData) == 0 || pktData[0] != 0x00 {
		return
	}

	// ── Packet 2: Status Request ───────────────────────────────────────────
	pktLen2, err := mcReadVarInt(c)
	if err != nil || pktLen2 < 1 {
		return
	}
	pktData2 := make([]byte, pktLen2)
	if _, err := io.ReadFull(c, pktData2); err != nil {
		return
	}
	if len(pktData2) == 0 || pktData2[0] != 0x00 {
		return
	}

	// ── Packet 3: Status Response ──────────────────────────────────────────
	statusJSON := mcStatusJSON()
	respPayload := mcWriteString(statusJSON)
	if _, err := c.Write(mcPacket(0x00, respPayload)); err != nil {
		return
	}

	// ── Packet 4+5: Ping / Pong (optional — many scanners skip this) ──────
	pingLen, err := mcReadVarInt(c)
	if err != nil || pingLen != 9 { // ping packet is always 9 bytes (1 VarInt ID + 8 bytes payload)
		return
	}
	pingData := make([]byte, pingLen)
	if _, err := io.ReadFull(c, pingData); err != nil {
		return
	}
	if pingData[0] != 0x01 {
		return
	}
	// Echo the 8-byte payload back as a pong
	pongPayload := pingData[1:]                 // 8 bytes
	_ = binary.LittleEndian.Uint64(pongPayload) // validate it's 8 bytes
	c.Write(mcPacket(0x01, pongPayload))        //nolint:errcheck
}

// startMinecraftListener binds to the Minecraft default port (25565) and
// emulates a Java Edition server-list-ping handshake.
func startMinecraftListener() {
	portStr := fmt.Sprintf("%d", minecraftPort)
	addr := fmt.Sprintf(":%d", minecraftPort)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Minecraft listener on %s failed: %v", addr, err)
		return
	}
	log.Printf("Minecraft listener on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Minecraft accept on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		go func(c net.Conn) {
			srcIP := extractConnIP(c.RemoteAddr())
			go handleCapture(srcIP, portStr, "tcp")
			handleMinecraftConn(c)
		}(conn)
	}
}

// portServiceName returns a human-readable service name for a given port number
// string, used by the history API to annotate events.
func portServiceName(port string) string {
	for p, name := range tcpServiceNames {
		if fmt.Sprintf("%d", p) == port {
			return name
		}
	}
	// HTTP capture ports
	switch port {
	case "80":
		return "HTTP"
	case "443":
		return "HTTPS"
	case "8080", "8000", "8008", "8081", "8088", "8090", "8888":
		return "HTTP-Alt"
	case "3000", "3001":
		return "Node/Dev"
	case "3128":
		return "Proxy"
	case "4000":
		return "Phoenix"
	case "4200":
		return "Angular"
	case "5000", "5001":
		return "Flask/Dev"
	case "9000":
		return "SonarQube"
	case "9090":
		return "Prometheus"
	case fmt.Sprintf("%d", minecraftPort):
		return "Minecraft"
	}
	for _, p := range udpServicePorts {
		if fmt.Sprintf("%d", p) == port {
			return "DNS"
		}
	}
	return port
}

// portsForService returns all port number strings whose service name matches
// the given name (case-insensitive). Used by the history query filter.
func portsForService(serviceName string) []string {
	upper := strings.ToUpper(serviceName)
	var result []string
	// Check all ports we know about
	allPorts := []string{}
	for _, svc := range tcpServices {
		allPorts = append(allPorts, fmt.Sprintf("%d", svc.Port))
	}
	for _, p := range capturePorts {
		allPorts = append(allPorts, fmt.Sprintf("%d", p))
	}
	for _, p := range udpServicePorts {
		allPorts = append(allPorts, fmt.Sprintf("%d", p))
	}
	allPorts = append(allPorts, fmt.Sprintf("%d", minecraftPort))

	seen := map[string]bool{}
	for _, p := range allPorts {
		if seen[p] {
			continue
		}
		seen[p] = true
		if strings.ToUpper(portServiceName(p)) == upper {
			result = append(result, p)
		}
	}
	return result
}
