package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// tcpServiceNames maps every port the app listens on to a display name.
// This is the canonical source used by portServiceName(), portsForService(),
// and the /api/services dropdown. It covers TCP service ports, UDP ports,
// HTTP capture ports, and the Minecraft port.
var tcpServiceNames = map[int]string{
	// TCP service ports (banner emulation)
	21:    "FTP",
	554:   "RTSP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	110:   "POP3",
	135:   "RPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	2375:  "Docker",
	3306:  "MySQL",
	3389:  "RDP",
	4444:  "Metasploit",
	5432:  "PostgreSQL",
	5555:  "ADB",
	5900:  "VNC",
	6000:  "X11",
	6379:  "Redis",
	6667:  "IRC",
	8443:  "HTTPS alt",
	9100:  "Printer",
	9200:  "Elasticsearch",
	11211: "Memcached",
	18789: "OpenClaw",
	27017: "MongoDB",
	// Cryptocurrency / blockchain ports
	3333:  "Stratum",
	8333:  "Bitcoin P2P",
	8545:  "Ethereum RPC",
	8546:  "Ethereum WS",
	9735:  "Lightning",
	10009: "Lightning gRPC",
	18080: "Monero P2P",
	18081: "Monero RPC",
	30303: "Ethereum P2P",
	// UDP capture ports
	53:   "DNS",
	123:  "NTP",
	161:  "SNMP",
	1434: "MSSQL Browser",
	1900: "SSDP",
	5060: "SIP",
	// HTTP capture ports
	80:   "HTTP",
	3000: "Node/Express",
	3001: "Node alt",
	3128: "Squid",
	4000: "Phoenix",
	4200: "Angular",
	5000: "Flask",
	5001: "Flask alt",
	8000: "HTTP alt",
	8008: "HTTP alt",
	8080: "HTTP proxy",
	8081: "HTTP proxy",
	8088: "HTTP alt",
	8090: "Confluence",
	8888: "Jupyter",
	9000: "SonarQube",
	9090: "Prometheus",
	// Minecraft
	25565: "Minecraft",
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
		Port: 135, // RPC (Microsoft DCE/RPC)
		Banner: func() []byte {
			// DCE/RPC bind_nak response — the standard rejection when a client
			// sends a bind request to an endpoint mapper that refuses the call.
			// Header: version=5, minor=0, type=0x0d (bind_nak), flags=0x03,
			// data_rep=little-endian, frag_len=28, auth_len=0, call_id=1,
			// reject_reason=0x02 (LOCAL_LIMIT_EXCEEDED), num_protocols=0
			return []byte{
				0x05, 0x00, // version 5.0
				0x0d,                   // packet type: bind_nak
				0x03,                   // flags: first+last frag
				0x10, 0x00, 0x00, 0x00, // data representation (LE, ASCII, IEEE)
				0x1c, 0x00, // frag length = 28
				0x00, 0x00, // auth length = 0
				0x01, 0x00, 0x00, 0x00, // call id = 1
				0x02, 0x00, // reject reason: LOCAL_LIMIT_EXCEEDED
				0x00, 0x00, 0x00, 0x00, // num protocols = 0 (padding)
			}
		},
	},
	{
		Port: 139, // NetBIOS Session Service
		Banner: func() []byte {
			// NetBIOS negative session response — sent when the server
			// rejects the session request. Type=0x83 (negative response),
			// length=1, error=0x80 (not listening on called name).
			return []byte{
				0x83,       // type: negative session response
				0x00,       // flags
				0x00, 0x01, // length = 1
				0x80, // error: not listening on called name
			}
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
		Port: 554, // RTSP (Real Time Streaming Protocol)
		Banner: func() []byte {
			// RTSP servers respond with a 200 OK to an OPTIONS request.
			// This mimics a generic IP camera or media server RTSP endpoint.
			return []byte("RTSP/1.0 200 OK\r\n" +
				"CSeq: 1\r\n" +
				"Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n" +
				"Server: GStreamer RTSP Server\r\n" +
				"\r\n")
		},
	},
	{
		Port: 993, // IMAP over SSL/TLS
		Banner: func() []byte {
			// Same TLS handshake_failure alert as port 443. Scanners probing
			// mail ports expect a TLS handshake; this is the correct rejection.
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 995, // POP3 over SSL/TLS
		Banner: func() []byte {
			// Same TLS handshake_failure alert as port 443/993.
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
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
		Port: 1521, // Oracle Database TNS Listener
		Banner: func() []byte {
			// TNS Refuse packet — the standard response from an Oracle TNS
			// listener that rejects a connection request. The refuse reason
			// mimics "no listener" which is what scanners expect from a
			// real Oracle instance that is not accepting connections.
			// Packet: type=4 (REFUSE), data includes refuse reason.
			reasonData := "(DESCRIPTION=(ERR=1153)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=1153)(EMFI=1))))"
			pktLen := 8 + len(reasonData) // TNS header (8 bytes) + data
			return append([]byte{
				byte(pktLen >> 8), byte(pktLen), // packet length (big-endian)
				0x00, 0x00, // packet checksum
				0x04,       // type: REFUSE
				0x00,       // reserved
				0x00, 0x00, // header checksum
			}, []byte(reasonData)...)
		},
	},
	{
		Port: 1723, // PPTP VPN
		Banner: func() []byte {
			// PPTP Start-Control-Connection-Reply (SCCRP) — the server's
			// response to a client's SCCRP request. This is a fixed 156-byte
			// message that indicates a PPTP VPN server is listening.
			reply := make([]byte, 156)
			// Length (2 bytes, big-endian) = 156
			reply[0] = 0x00
			reply[1] = 0x9c
			// PPTP Message Type: Control Message (1)
			reply[2] = 0x00
			reply[3] = 0x01
			// Magic Cookie: 0x1A2B3C4D
			reply[4] = 0x1a
			reply[5] = 0x2b
			reply[6] = 0x3c
			reply[7] = 0x4d
			// Control Message Type: Start-Control-Connection-Reply (2)
			reply[8] = 0x00
			reply[9] = 0x02
			// Reserved
			reply[10] = 0x00
			reply[11] = 0x00
			// Protocol Version: 1.0
			reply[12] = 0x01
			reply[13] = 0x00
			// Result Code: 1 (Successful channel establishment)
			reply[14] = 0x01
			// Error Code: 0 (None)
			reply[15] = 0x00
			// Framing Capabilities: async + sync
			reply[16] = 0x00
			reply[17] = 0x00
			reply[18] = 0x00
			reply[19] = 0x03
			// Bearer Capabilities: analog + digital
			reply[20] = 0x00
			reply[21] = 0x00
			reply[22] = 0x00
			reply[23] = 0x03
			// Maximum Channels: 1
			reply[24] = 0x00
			reply[25] = 0x01
			// Firmware Revision: 1
			reply[26] = 0x00
			reply[27] = 0x01
			// Host Name (64 bytes at offset 28): "pptp-server"
			copy(reply[28:], "pptp-server")
			// Vendor String (64 bytes at offset 92): "linux"
			copy(reply[92:], "linux")
			return reply
		},
	},
	{
		Port: 2375, // Docker API (unencrypted)
		Banner: func() []byte {
			// Docker daemon's REST API returns a JSON version response
			// when queried at GET /version or GET /_ping. Scanners send
			// an HTTP GET and look for Docker-specific headers/JSON.
			// This mimics the /_ping endpoint (simplest fingerprint).
			return []byte("HTTP/1.1 200 OK\r\n" +
				"Api-Version: 1.45\r\n" +
				"Docker-Experimental: false\r\n" +
				"Ostype: linux\r\n" +
				"Server: Docker/25.0.3 (linux)\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\n" +
				"Content-Length: 2\r\n" +
				"\r\n" +
				"OK")
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
		Port: 4444, // Metasploit default reverse shell
		Banner: func() []byte {
			// Port 4444 is the default Meterpreter reverse shell port. There is
			// no standard protocol banner — a real compromised host would just
			// accept the connection silently. We send nothing; the connection
			// accept itself is the event that matters.
			return nil
		},
	},
	{
		Port: 5432, // PostgreSQL
		Banner: func() []byte {
			// PostgreSQL ErrorResponse sent when a client connects without a
			// valid pg_hba.conf entry. Format per the PG wire protocol:
			//   'E' (message type, outside the length)
			//   int32 length (includes itself, not the type byte)
			//   then field entries: type_char + string + \0 ...
			//   terminated by \0
			// Field types: 'S' = severity, 'V' = severity (non-localized),
			// 'C' = SQLSTATE code, 'M' = message.
			fields := []byte(
				"SFATAL\x00" +
					"VFATAL\x00" +
					"C28000\x00" +
					"Mno pg_hba.conf entry for host\x00" +
					"\x00", // terminator
			)
			length := 4 + len(fields) // int32 length includes itself
			hdr := []byte{
				'E',
				byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
			}
			return append(hdr, fields...)
		},
	},
	{
		Port: 5555, // Android Debug Bridge (ADB)
		Banner: func() []byte {
			// ADB protocol CNXN (connect) response. This is the first message
			// an ADB daemon sends after accepting a TCP connection. The format
			// is: command(4) + arg0(4) + arg1(4) + data_length(4) + data_crc(4) + magic(4)
			// followed by the system identity string.
			// command: "CNXN" = 0x4e584e43
			// arg0: version (0x01000000 = version 1.0)
			// arg1: max data (4096 = 0x00001000)
			identity := "device::ro.product.model=Android;ro.product.device=generic\x00"
			dataLen := len(identity)
			// Simple checksum: sum of all bytes in data
			var crc uint32
			for _, b := range []byte(identity) {
				crc += uint32(b)
			}
			hdr := []byte{
				// CNXN command (little-endian)
				0x43, 0x4e, 0x58, 0x4e,
				// version 1.0
				0x00, 0x00, 0x00, 0x01,
				// max data: 4096
				0x00, 0x10, 0x00, 0x00,
				// data length
				byte(dataLen), byte(dataLen >> 8), byte(dataLen >> 16), byte(dataLen >> 24),
				// data crc32
				byte(crc), byte(crc >> 8), byte(crc >> 16), byte(crc >> 24),
				// magic: CNXN ^ 0xFFFFFFFF
				0xbc, 0xb1, 0xa7, 0xb1,
			}
			return append(hdr, []byte(identity)...)
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
		Port: 6667, // IRC
		Banner: func() []byte {
			// IRC server welcome — the standard sequence an IRC daemon sends
			// upon connection. Includes a NOTICE AUTH and RPL_YOURHOST-style
			// response. Scanners and botnets probing for IRC C&C servers
			// expect this exact pattern.
			return []byte(":irc.localhost NOTICE AUTH :*** Looking up your hostname...\r\n" +
				":irc.localhost NOTICE AUTH :*** Found your hostname\r\n")
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
	// Port 5900 (VNC) is handled by startVNCListener() — it completes the
	// full RFB version + security handshake so clients get a clean refusal
	// instead of retrying endlessly after a mid-handshake disconnect.
	{
		Port: 6000, // X11 (X Window System)
		Banner: func() []byte {
			// X11 servers send a connection-refused response when they reject
			// a client. The X11 protocol initial response: 0x00 = Failed,
			// then reason-length, protocol version, additional-data-length,
			// and a human-readable reason string.
			reason := "No protocol specified"
			padded := len(reason)
			if padded%4 != 0 {
				padded += 4 - padded%4
			}
			addlData := (padded) / 4 // in 4-byte units
			resp := make([]byte, 8+padded)
			resp[0] = 0x00                // Failed
			resp[1] = byte(len(reason))   // reason length
			resp[2] = 0x00                // protocol-major-version (11) LE
			resp[3] = 0x0b                // ...high byte
			resp[4] = 0x00                // protocol-minor-version (0) LE
			resp[5] = 0x00                // ...high byte
			resp[6] = byte(addlData)      // additional data length (4-byte units) LE
			resp[7] = byte(addlData >> 8) // ...high byte
			copy(resp[8:], reason)
			return resp
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
		Port: 9100, // HP JetDirect / Printer
		Banner: func() []byte {
			// PJL (Printer Job Language) ready response. HP JetDirect printers
			// and print servers respond with a PJL info status when probed.
			// This is what Shodan and mass-scanners fingerprint as "printer".
			return []byte("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n")
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
	// ── Cryptocurrency / Blockchain services ─────────────────────────────
	{
		Port: 3333, // Stratum Mining Protocol
		Banner: func() []byte {
			// Stratum mining servers send a JSON-RPC notification on connect.
			// This mimics a mining pool ready response that scanners expect.
			return []byte(`{"id":null,"method":"mining.notify","params":["0001","` +
				`00000000000000000000000000000000000000000000000000000000` +
				`00000000","01000000010000000000000000000000000000000000` +
				`00000000000000000000000000ffffffff","07040700","00000001",` +
				`[],"00000002","1d00ffff","64000000",true]}` + "\n")
		},
	},
	{
		Port: 8333, // Bitcoin P2P
		Banner: func() []byte {
			// Bitcoin protocol version message. This is the first message a
			// Bitcoin node sends after accepting a connection. The format is:
			// magic(4) + command(12) + payload_length(4) + checksum(4) + payload
			// Magic: 0xF9BEB4D9 (mainnet)
			// Command: "version" padded to 12 bytes
			// We send a minimal version message that identifies as Bitcoin Core 25.0
			magic := []byte{0xf9, 0xbe, 0xb4, 0xd9}
			cmd := make([]byte, 12)
			copy(cmd, "version")
			// Minimal payload: version(4) + services(8) + timestamp(8) +
			// addr_recv(26) + addr_from(26) + nonce(8) + user_agent_len(1) +
			// user_agent + start_height(4) + relay(1)
			userAgent := "/Satoshi:25.0.0/"
			payloadLen := 4 + 8 + 8 + 26 + 26 + 8 + 1 + len(userAgent) + 4 + 1
			payload := make([]byte, payloadLen)
			// Protocol version: 70016
			payload[0] = 0x80
			payload[1] = 0x11
			payload[2] = 0x01
			payload[3] = 0x00
			// Services: NODE_NETWORK (1)
			payload[4] = 0x01
			// Timestamp: zeros (good enough for a banner)
			// addr_recv and addr_from: zeros
			// Nonce: arbitrary
			payload[46] = 0x42
			// User agent
			uaOffset := 4 + 8 + 8 + 26 + 26 + 8
			payload[uaOffset] = byte(len(userAgent))
			copy(payload[uaOffset+1:], userAgent)
			// Start height: 850000 (0x000CF850)
			heightOffset := uaOffset + 1 + len(userAgent)
			payload[heightOffset] = 0x50
			payload[heightOffset+1] = 0xf8
			payload[heightOffset+2] = 0x0c
			payload[heightOffset+3] = 0x00
			// Relay: true
			payload[heightOffset+4] = 0x01

			// Payload length (little-endian uint32)
			pLen := make([]byte, 4)
			pLen[0] = byte(payloadLen)
			pLen[1] = byte(payloadLen >> 8)
			pLen[2] = byte(payloadLen >> 16)
			pLen[3] = byte(payloadLen >> 24)
			// Checksum: first 4 bytes of double-SHA256 of payload — use zeros
			// (close enough; real nodes will disconnect but scanners just fingerprint)
			checksum := []byte{0x00, 0x00, 0x00, 0x00}

			msg := make([]byte, 0, 4+12+4+4+payloadLen)
			msg = append(msg, magic...)
			msg = append(msg, cmd...)
			msg = append(msg, pLen...)
			msg = append(msg, checksum...)
			msg = append(msg, payload...)
			return msg
		},
	},
	{
		Port: 8545, // Ethereum JSON-RPC
		Banner: func() []byte {
			// Ethereum JSON-RPC endpoints return an HTTP 200 with a JSON-RPC
			// error when no method is provided. This is the #1 target for
			// crypto-draining bots — an exposed RPC means wallet access.
			body := `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}`
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
				"Content-Type: application/json\r\n"+
				"Content-Length: %d\r\n"+
				"\r\n%s", len(body), body))
		},
	},
	{
		Port: 8546, // Ethereum WebSocket RPC
		Banner: func() []byte {
			// WebSocket endpoint — scanners send an HTTP upgrade request.
			// Return 426 like a real geth node that requires WS upgrade.
			return []byte("HTTP/1.1 426 Upgrade Required\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Content-Type: text/plain\r\n" +
				"Content-Length: 22\r\n" +
				"\r\n" +
				"WebSocket upgrade only")
		},
	},
	// Port 9735 (Lightning) is handled by startLightningListener() — it
	// requires reading the client's Act One before replying with Act Two,
	// which doesn't fit the send-banner-and-close model.
	{
		Port: 10009, // Lightning Network gRPC (lnd)
		Banner: func() []byte {
			// lnd's gRPC endpoint uses HTTP/2. Send a minimal HTTP/2
			// connection preface (server settings frame) that scanners
			// recognize as an active gRPC endpoint.
			// HTTP/2 SETTINGS frame: length=0, type=0x04, flags=0, stream=0
			return []byte{
				0x00, 0x00, 0x00, // length: 0
				0x04,                   // type: SETTINGS
				0x00,                   // flags
				0x00, 0x00, 0x00, 0x00, // stream ID: 0
			}
		},
	},
	{
		Port: 18080, // Monero P2P (monerod)
		Banner: func() []byte {
			// Monero's Levin protocol sends a handshake response. The header
			// starts with the Levin signature (0x0121010101010101) followed by
			// the data length, flags, and command fields.
			// We send a minimal Levin bucket header indicating a handshake
			// response (command 1001), then close.
			return []byte{
				0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // Levin signature
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data length: 0
				0x01,             // expect response: false
				0x00, 0x00, 0x00, // flags: response
				0x00, 0x00, 0x00, 0x01, // flags contd (Q_NORMAL_RESPONSE)
				0xe9, 0x03, 0x00, 0x00, // command: 1001 (HANDSHAKE)
				0x00, 0x00, 0x00, 0x00, // return code: 0 (OK)
			}
		},
	},
	{
		Port: 18081, // Monero RPC (monerod JSON-RPC)
		Banner: func() []byte {
			// Monero's restricted RPC returns a JSON-RPC error on invalid requests.
			body := `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}`
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
				"Content-Type: application/json\r\n"+
				"Content-Length: %d\r\n"+
				"\r\n%s", len(body), body))
		},
	},
	{
		Port: 30303, // Ethereum P2P (devp2p/RLPx)
		Banner: func() []byte {
			// Ethereum's RLPx protocol starts with an ECIES encrypted
			// handshake (EIP-8). The initiator sends an auth message;
			// the responder sends an ack. We don't actually do crypto,
			// but sending nothing is fine — the connection accept is the
			// event. Real geth nodes wait for the initiator's auth first.
			return nil
		},
	},
}

// udpServicePorts are the UDP ports webTraffik captures.
// We bind, read one datagram to get the source address, fire the event, and discard the payload.
var udpServicePorts = []int{
	53,    // DNS
	123,   // NTP
	161,   // SNMP
	1434,  // MSSQL Browser/Monitor
	1900,  // SSDP/UPnP
	5060,  // SIP
	30303, // Ethereum P2P (devp2p discovery)
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
			// Drop banned IPs before sending the banner.
			if appLimiter.IsBanned(srcIP, portStr) {
				return
			}
			banner := svc.Banner()
			if len(banner) > 0 {
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				c.Write(banner) //nolint:errcheck
			}
			// Read up to 256 bytes of client data after the banner.
			// This captures what the scanner/client sends (auth attempts,
			// protocol negotiation, exploit payloads, etc.).
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			clientBuf := make([]byte, 256)
			n, _ := c.Read(clientBuf)
			go handleCapture(srcIP, portStr, "tcp", clientBuf[:n])
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
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read on %s: %v", addr, err)
			time.Sleep(time.Second)
			continue
		}
		srcIP := extractConnIP(src)
		// Copy the datagram payload (up to 256 bytes) before the next ReadFrom
		// overwrites the buffer.
		clientData := make([]byte, min(n, 256))
		copy(clientData, buf[:min(n, 256)])
		go handleCapture(srcIP, portStr, "udp", clientData)
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

// ── VNC (RFB) version exchange with tarpit ────────────────────────────────────
//
// First connection from an IP:
//   1. Server → Client: "RFB 003.008\n"   (protocol version)
//   2. Client → Server: "RFB 003.0xx\n"   (client version — captured)
//   3. Connection closed silently
//
// Repeat connections from the same IP within vncTarpitWindow:
//   Steps 1–2 as above (still captured), then the connection is held open
//   for a random 10–30 second delay before closing. This ties up a thread
//   in the scanner's connection pool, throttling their scan rate without
//   revealing that anything unusual is happening.

const vncPort = 5900
const vncTarpitWindow = 60 * time.Second // window to consider an IP "repeat"
const vncTarpitMin = 10 * time.Second
const vncTarpitMax = 30 * time.Second

var (
	vncSeenMu  sync.Mutex
	vncSeenIPs = make(map[string]time.Time) // IP → last seen time
)

func vncIsRepeat(ip string) bool {
	vncSeenMu.Lock()
	defer vncSeenMu.Unlock()
	last, ok := vncSeenIPs[ip]
	now := time.Now()
	vncSeenIPs[ip] = now
	return ok && now.Sub(last) < vncTarpitWindow
}

func startVNCListener() {
	portStr := fmt.Sprintf("%d", vncPort)
	addr := fmt.Sprintf(":%d", vncPort)

	// Periodically prune stale entries from the seen-IP map so it doesn't
	// grow unbounded on a long-running server.
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
			if appLimiter.IsBanned(srcIP, portStr) {
				return
			}
			repeat := vncIsRepeat(srcIP)
			clientData := handleVNCConn(c, repeat)
			go handleCapture(srcIP, portStr, "tcp", clientData)
		}(conn)
	}
}

func handleVNCConn(c net.Conn, tarpit bool) []byte {
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// Step 1: Server sends protocol version
	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return nil
	}

	// Step 2: Read client version (12 bytes) — captured payload
	clientVersion := make([]byte, 12)
	if _, err := io.ReadFull(c, clientVersion); err != nil {
		return nil
	}

	if tarpit {
		// Hold the connection open for a random 10–30s before closing.
		// This ties up a slot in the scanner's connection pool, throttling
		// their rate without signalling anything unusual.
		hold := vncTarpitMin + time.Duration(rand.Int63n(int64(vncTarpitMax-vncTarpitMin)))
		c.SetDeadline(time.Now().Add(hold + 5*time.Second))
		time.Sleep(hold)
	}

	return clientVersion
}

// ── Lightning Network P2P (BOLT #8) emulator ─────────────────────────────────
//
// Protocol reference: BOLT #8 — Encrypted and Authenticated Transport
//
// The Noise_XK handshake has three acts:
//   1. Initiator → Responder: Act One  (50 bytes)
//   2. Responder → Initiator: Act Two  (50 bytes)
//   3. Initiator → Responder: Act Three (66 bytes)
//
// We read Act One from the client, then send a fake Act Two response.
// Scanners probing for Lightning nodes expect this read-then-reply pattern.

const lightningPort = 9735

// startLightningListener binds to port 9735 and emulates the BOLT #8
// Noise_XK handshake: reads the client's 50-byte Act One, then sends
// a 50-byte Act Two response.
func startLightningListener() {
	portStr := fmt.Sprintf("%d", lightningPort)
	addr := fmt.Sprintf(":%d", lightningPort)

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
			if appLimiter.IsBanned(srcIP, portStr) {
				return
			}
			clientData := handleLightningConn(c)
			go handleCapture(srcIP, portStr, "tcp", clientData)
		}(conn)
	}
}

// handleLightningConn processes a single Lightning Network connection:
// reads the 50-byte Act One from the initiator, then sends a 50-byte
// Act Two response, then closes. Returns the Act One bytes as client data.
func handleLightningConn(c net.Conn) []byte {
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// Read Act One: 1 byte version + 33 bytes ephemeral pubkey + 16 bytes tag = 50 bytes
	actOne := make([]byte, 50)
	if _, err := io.ReadFull(c, actOne); err != nil {
		return nil
	}

	// Send Act Two: 1 byte version + 33 bytes ephemeral pubkey + 16 bytes tag = 50 bytes
	// We generate deterministic but realistic-looking bytes since we can't
	// actually perform the Noise_XK crypto without a real static key.
	actTwo := make([]byte, 50)
	actTwo[0] = 0x00 // version byte (must be 0)
	for i := 1; i < 50; i++ {
		actTwo[i] = byte((i * 37) ^ 0xAB)
	}
	c.Write(actTwo) //nolint:errcheck
	return actOne
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
// echoes the ping, then closes. Returns the raw handshake packet as client data.
func handleMinecraftConn(c net.Conn) []byte {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// ── Packet 1: Handshake ────────────────────────────────────────────────
	// Read framing length
	pktLen, err := mcReadVarInt(c)
	if err != nil || pktLen <= 0 || pktLen > 512 {
		return nil
	}
	pktData := make([]byte, pktLen)
	if _, err := io.ReadFull(c, pktData); err != nil {
		return nil
	}
	// We don't need to parse the handshake contents; just verify packet ID = 0x00.
	if len(pktData) == 0 || pktData[0] != 0x00 {
		return pktData // return whatever they sent even if unexpected
	}

	// Capture the handshake packet for client data (contains protocol version,
	// server address, port, and next state).
	clientData := pktData

	// ── Packet 2: Status Request ───────────────────────────────────────────
	pktLen2, err := mcReadVarInt(c)
	if err != nil || pktLen2 < 1 {
		return clientData
	}
	pktData2 := make([]byte, pktLen2)
	if _, err := io.ReadFull(c, pktData2); err != nil {
		return clientData
	}
	if len(pktData2) == 0 || pktData2[0] != 0x00 {
		return clientData
	}

	// ── Packet 3: Status Response ──────────────────────────────────────────
	statusJSON := mcStatusJSON()
	respPayload := mcWriteString(statusJSON)
	if _, err := c.Write(mcPacket(0x00, respPayload)); err != nil {
		return clientData
	}

	// ── Packet 4+5: Ping / Pong (optional — many scanners skip this) ──────
	pingLen, err := mcReadVarInt(c)
	if err != nil || pingLen != 9 { // ping packet is always 9 bytes (1 VarInt ID + 8 bytes payload)
		return clientData
	}
	pingData := make([]byte, pingLen)
	if _, err := io.ReadFull(c, pingData); err != nil {
		return clientData
	}
	if pingData[0] != 0x01 {
		return clientData
	}
	// Echo the 8-byte payload back as a pong
	pongPayload := pingData[1:]                 // 8 bytes
	_ = binary.LittleEndian.Uint64(pongPayload) // validate it's 8 bytes
	c.Write(mcPacket(0x01, pongPayload))        //nolint:errcheck
	return clientData
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
			// Drop banned IPs before running the Minecraft handshake.
			if appLimiter.IsBanned(srcIP, portStr) {
				c.Close()
				return
			}
			clientData := handleMinecraftConn(c)
			go handleCapture(srcIP, portStr, "tcp", clientData)
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
	return port
}

// portsForService returns all port number strings whose service name matches
// the given name (case-insensitive). Used by the history query filter.
func portsForService(serviceName string) []string {
	upper := strings.ToUpper(serviceName)
	var result []string
	for p, name := range tcpServiceNames {
		if strings.ToUpper(name) == upper {
			result = append(result, fmt.Sprintf("%d", p))
		}
	}
	return result
}
