package services

import "fmt"

// tcpServices is the list of non-HTTP TCP services webTraffik emulates.
// Port 5900 (VNC), 9735 (Lightning), and 25565 (Minecraft) are handled by their
// own dedicated listeners (startVNCListener, startLightningListener,
// startMinecraftListener) because they require interactive protocol exchanges.
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
			// DCE/RPC bind_nak response
			return []byte{
				0x05, 0x00,
				0x0d,
				0x03,
				0x10, 0x00, 0x00, 0x00,
				0x1c, 0x00,
				0x00, 0x00,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}
		},
	},
	{
		Port: 139, // NetBIOS Session Service
		Banner: func() []byte {
			return []byte{
				0x83,
				0x00,
				0x00, 0x01,
				0x80,
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
		Port: 443, // HTTPS — TLS handshake_failure alert
		Banner: func() []byte {
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 445, // SMB
		Banner: func() []byte {
			return []byte{
				0x00, 0x00, 0x00, 0x54,
				0xFE, 'S', 'M', 'B',
				0x40, 0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0xC0,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}
		},
	},
	{
		Port: 554, // RTSP — impersonates a Hikvision IP camera
		Banner: func() []byte {
			// Hikvision cameras respond to any RTSP request with 401 Unauthorized,
			// demanding Digest auth. This is the fingerprint scanners look for.
			return []byte("RTSP/1.0 401 Unauthorized\r\n" +
				"CSeq: 1\r\n" +
				"WWW-Authenticate: Digest realm=\"IP Camera(C6473WD)\", nonce=\"4f3a9c1b7e2d8f05\", algorithm=\"MD5\"\r\n" +
				"Server: Hikvision-Webs\r\n" +
				"\r\n")
		},
	},
	{
		Port: 993, // IMAP over SSL/TLS
		Banner: func() []byte {
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 995, // POP3 over SSL/TLS
		Banner: func() []byte {
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 1433, // MSSQL
		Banner: func() []byte {
			return []byte{
				0x04,
				0x01,
				0x00, 0x25,
				0x00, 0x00,
				0x01,
				0x00,
				0x00, 0x00, 0x15, 0x00, 0x06,
				0x01, 0x00, 0x1b, 0x00, 0x01,
				0xff,
				0x0f, 0x00, 0x07, 0xd0, 0x00, 0x05,
				0x02,
			}
		},
	},
	{
		Port: 1521, // Oracle Database TNS Listener
		Banner: func() []byte {
			reasonData := "(DESCRIPTION=(ERR=1153)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=1153)(EMFI=1))))"
			pktLen := 8 + len(reasonData)
			return append([]byte{
				byte(pktLen >> 8), byte(pktLen),
				0x00, 0x00,
				0x04,
				0x00,
				0x00, 0x00,
			}, []byte(reasonData)...)
		},
	},
	{
		Port: 1723, // PPTP VPN
		Banner: func() []byte {
			reply := make([]byte, 156)
			reply[0] = 0x00
			reply[1] = 0x9c
			reply[2] = 0x00
			reply[3] = 0x01
			reply[4] = 0x1a
			reply[5] = 0x2b
			reply[6] = 0x3c
			reply[7] = 0x4d
			reply[8] = 0x00
			reply[9] = 0x02
			reply[10] = 0x00
			reply[11] = 0x00
			reply[12] = 0x01
			reply[13] = 0x00
			reply[14] = 0x01
			reply[15] = 0x00
			reply[16] = 0x00
			reply[17] = 0x00
			reply[18] = 0x00
			reply[19] = 0x03
			reply[20] = 0x00
			reply[21] = 0x00
			reply[22] = 0x00
			reply[23] = 0x03
			reply[24] = 0x00
			reply[25] = 0x01
			reply[26] = 0x00
			reply[27] = 0x01
			copy(reply[28:], "pptp-server")
			copy(reply[92:], "linux")
			return reply
		},
	},
	{
		Port: 2375, // Docker API (unencrypted)
		Banner: func() []byte {
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
			serverVersion := "8.0.35\x00"
			pkt := []byte{0x0a}
			pkt = append(pkt, []byte(serverVersion)...)
			pkt = append(pkt,
				0x01, 0x00, 0x00, 0x00,
				0x52, 0x59, 0x41, 0x4e, 0x44, 0x4f, 0x4d, 0x58,
				0x00,
				0x02, 0xff,
				0x21,
				0x02, 0x00,
				0x7f, 0xff,
				0x15,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x53, 0x54, 0x52, 0x4f, 0x4e, 0x47, 0x50, 0x41, 0x53, 0x53, 0x57, 0x44, 0x00,
				0x63, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68, 0x61, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
			)
			length := len(pkt)
			framed := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0x00}
			return append(framed, pkt...)
		},
	},
	{
		Port: 3389, // RDP
		Banner: func() []byte {
			return []byte{
				0x03, 0x00,
				0x00, 0x13,
				0x0e,
				0xd0,
				0x00, 0x00,
				0x00, 0x00,
				0x00,
				0x02,
				0x00,
				0x08, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}
		},
	},
	{
		Port: 4444, // Metasploit default reverse shell — no banner
		Banner: func() []byte {
			return nil
		},
	},
	{
		Port: 5432, // PostgreSQL
		Banner: func() []byte {
			fields := []byte(
				"SFATAL\x00" +
					"VFATAL\x00" +
					"C28000\x00" +
					"Mno pg_hba.conf entry for host\x00" +
					"\x00",
			)
			length := 4 + len(fields)
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
			identity := "device::ro.product.model=Android;ro.product.device=generic\x00"
			dataLen := len(identity)
			var crc uint32
			for _, b := range []byte(identity) {
				crc += uint32(b)
			}
			hdr := []byte{
				0x43, 0x4e, 0x58, 0x4e,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x10, 0x00, 0x00,
				byte(dataLen), byte(dataLen >> 8), byte(dataLen >> 16), byte(dataLen >> 24),
				byte(crc), byte(crc >> 8), byte(crc >> 16), byte(crc >> 24),
				0xbc, 0xb1, 0xa7, 0xb1,
			}
			return append(hdr, []byte(identity)...)
		},
	},
	{
		Port: 6379, // Redis
		Banner: func() []byte {
			return []byte("-DENIED Redis is running in protected mode\r\n")
		},
	},
	{
		Port: 6667, // IRC
		Banner: func() []byte {
			return []byte(":irc.localhost NOTICE AUTH :*** Looking up your hostname...\r\n" +
				":irc.localhost NOTICE AUTH :*** Found your hostname\r\n")
		},
	},
	{
		Port: 27017, // MongoDB
		Banner: func() []byte {
			bsonDoc := []byte{
				0x00, 0x00, 0x00, 0x00,
				0x01, 'o', 'k', 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 'e', 'r', 'r', 'm', 's', 'g', 0x00,
				0x17, 0x00, 0x00, 0x00,
				'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'r', 'e', 'q', 'u', 'i', 'r', 'e', 'd', 0x00,
				0x10, 'c', 'o', 'd', 'e', 0x00,
				0x0d, 0x00, 0x00, 0x00,
				0x00,
			}
			docLen := len(bsonDoc)
			bsonDoc[0] = byte(docLen)
			bsonDoc[1] = byte(docLen >> 8)
			bsonDoc[2] = byte(docLen >> 16)
			bsonDoc[3] = byte(docLen >> 24)

			msgLen := 16 + 4 + 4 + 4 + 4 + len(bsonDoc)
			hdr := []byte{
				byte(msgLen), byte(msgLen >> 8), byte(msgLen >> 16), byte(msgLen >> 24),
				0x01, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00,
			}
			return append(hdr, bsonDoc...)
		},
	},
	{
		Port: 6000, // X11
		Banner: func() []byte {
			reason := "No protocol specified"
			padded := len(reason)
			if padded%4 != 0 {
				padded += 4 - padded%4
			}
			addlData := (padded) / 4
			resp := make([]byte, 8+padded)
			resp[0] = 0x00
			resp[1] = byte(len(reason))
			resp[2] = 0x00
			resp[3] = 0x0b
			resp[4] = 0x00
			resp[5] = 0x00
			resp[6] = byte(addlData)
			resp[7] = byte(addlData >> 8)
			copy(resp[8:], reason)
			return resp
		},
	},
	{
		Port: 8443, // HTTPS alt
		Banner: func() []byte {
			return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
		},
	},
	{
		Port: 9100, // HP JetDirect / Printer
		Banner: func() []byte {
			return []byte("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\nONLINE=TRUE\r\n")
		},
	},
	{
		Port: 9200, // Elasticsearch
		Banner: func() []byte {
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
			return []byte("ERROR\r\n")
		},
	},
	{
		Port: 18789, // OpenClaw Gateway
		Banner: func() []byte {
			return []byte("HTTP/1.1 426 Upgrade Required\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Content-Type: text/plain\r\n" +
				"Content-Length: 25\r\n" +
				"\r\n" +
				"WebSocket upgrade required")
		},
	},
	// ── Cryptocurrency / Blockchain services ──────────────────────────────
	{
		Port: 3333, // Stratum Mining Protocol
		Banner: func() []byte {
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
			magic := []byte{0xf9, 0xbe, 0xb4, 0xd9}
			cmd := make([]byte, 12)
			copy(cmd, "version")
			userAgent := "/Satoshi:25.0.0/"
			payloadLen := 4 + 8 + 8 + 26 + 26 + 8 + 1 + len(userAgent) + 4 + 1
			payload := make([]byte, payloadLen)
			payload[0] = 0x80
			payload[1] = 0x11
			payload[2] = 0x01
			payload[3] = 0x00
			payload[4] = 0x01
			payload[46] = 0x42
			uaOffset := 4 + 8 + 8 + 26 + 26 + 8
			payload[uaOffset] = byte(len(userAgent))
			copy(payload[uaOffset+1:], userAgent)
			heightOffset := uaOffset + 1 + len(userAgent)
			payload[heightOffset] = 0x50
			payload[heightOffset+1] = 0xf8
			payload[heightOffset+2] = 0x0c
			payload[heightOffset+3] = 0x00
			payload[heightOffset+4] = 0x01

			pLen := make([]byte, 4)
			pLen[0] = byte(payloadLen)
			pLen[1] = byte(payloadLen >> 8)
			pLen[2] = byte(payloadLen >> 16)
			pLen[3] = byte(payloadLen >> 24)
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
			return []byte("HTTP/1.1 426 Upgrade Required\r\n" +
				"Connection: Upgrade\r\n" +
				"Upgrade: websocket\r\n" +
				"Content-Type: text/plain\r\n" +
				"Content-Length: 22\r\n" +
				"\r\n" +
				"WebSocket upgrade only")
		},
	},
	{
		Port: 10009, // Lightning Network gRPC (lnd) — HTTP/2 SETTINGS frame
		Banner: func() []byte {
			return []byte{
				0x00, 0x00, 0x00,
				0x04,
				0x00,
				0x00, 0x00, 0x00, 0x00,
			}
		},
	},
	{
		Port: 18080, // Monero P2P (monerod)
		Banner: func() []byte {
			return []byte{
				0x01, 0x21, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01,
				0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0xe9, 0x03, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}
		},
	},
	{
		Port: 18081, // Monero RPC
		Banner: func() []byte {
			body := `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}`
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
				"Content-Type: application/json\r\n"+
				"Content-Length: %d\r\n"+
				"\r\n%s", len(body), body))
		},
	},
	{
		Port: 30303, // Ethereum P2P (devp2p/RLPx) — no banner; connection accept is the event
		Banner: func() []byte {
			return nil
		},
	},
	// ── IP Camera / DVR honeypot services ────────────────────────────────────
	{
		Port: 8899, // Hikvision IP camera HTTP web UI
		Banner: func() []byte {
			// Hikvision cameras serve a redirect to their web login on the root path.
			// Scanners (and Shodan) fingerprint this specific Server header + redirect.
			body := "<html><body><a href=\"/doc/page/login.asp\">Object Moved</a></body></html>"
			return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
				"Content-Type: text/html\r\n"+
				"Content-Length: %d\r\n"+
				"Server: App-webs/\r\n"+
				"X-Frame-Options: SAMEORIGIN\r\n"+
				"\r\n"+
				"%s", len(body), body))
		},
	},
	{
		Port: 37777, // Dahua DVR/NVR proprietary TCP protocol
		Banner: func() []byte {
			// Dahua devices respond with a fixed 20-byte challenge packet.
			// Byte layout: 0xFF 0x01 (magic), 0x00 0x00 (reserved),
			// 4-byte session ID, 4-byte sequence, 4-byte data length,
			// 4-byte result code (0 = OK), 2-byte error code.
			// This is the fingerprint mass-scanners use to identify Dahua DVRs.
			return []byte{
				0xff, 0x01, // magic
				0x00, 0x00, // reserved
				0xa1, 0xb2, 0xc3, 0xd4, // session ID
				0x00, 0x00, 0x00, 0x01, // sequence
				0x00, 0x00, 0x00, 0x00, // data length (no payload)
				0x00, 0x00, 0x00, 0x00, // result code 0 (success/challenge)
			}
		},
	},
	{
		Port: 34567, // XMEye / generic DVR clone (Hikvision-derivative firmware)
		Banner: func() []byte {
			// XMEye protocol: JSON-over-TCP with a fixed 20-byte header.
			// Header: magic 0xff 0x00 0x00 0x00, session 0x00000000,
			// sequence LE uint32, channel 0x00, end flags 0x00 0x00,
			// message type LE uint16 (0x03E8 = login response),
			// payload length LE uint32.
			// Payload is a JSON login challenge — the exact string real XMEye
			// devices send when a client connects without credentials.
			payload := []byte(`{"AlarmState":"","DeviceType ":"DVR","Ret":100,"SessionID":"0x00000001"}`)
			pLen := len(payload)
			hdr := []byte{
				0xff, 0x00, 0x00, 0x00, // magic
				0x00, 0x00, 0x00, 0x00, // session ID
				0x01, 0x00, 0x00, 0x00, // sequence = 1
				0x00,       // channel
				0x00, 0x00, // end flags
				0xe8, 0x03, // message type 1000 (login response) LE
				byte(pLen), byte(pLen >> 8), byte(pLen >> 16), byte(pLen >> 24),
			}
			return append(hdr, payload...)
		},
	},
}

// ── Industrial / SCADA services ───────────────────────────────────────────────
// These are appended separately for clarity; StartTCPServiceListeners ranges
// over the single tcpServices slice which includes all entries below.
func init() {
	tcpServices = append(tcpServices,
		// ── Industrial / SCADA ────────────────────────────────────────────────
		serviceEntry{
			Port: 102, // Siemens S7comm (ISO-TSAP) — PLCs, HMIs
			Banner: func() []byte {
				// ISO-TSAP Connection Confirm (CC) TPDU — the response a real
				// Siemens S7-300/400 PLC sends after a client COTP connect request.
				// Scanners (and Shodan's "siemens" filter) fingerprint this exact
				// 22-byte CC packet.
				return []byte{
					0x03, 0x00, // TPKT version 3
					0x00, 0x16, // TPKT length = 22
					0x11,       // COTP length = 17
					0xd0,       // COTP PDU type: CC (Connection Confirm)
					0x00, 0x01, // dst reference
					0x00, 0x01, // src reference
					0x00, // class / options
					// COTP parameters: tpdu-size(0xc0), calling/called TSAP
					0xc0, 0x01, 0x0a, // tpdu-size = 1024
					0xc1, 0x02, 0x01, 0x00, // calling TSAP
					0xc2, 0x02, 0x01, 0x02, // called TSAP (rack 0, slot 2 — S7-300 default)
				}
			},
		},
		serviceEntry{
			Port: 502, // Modbus/TCP — industrial control, completely unauthenticated
			Banner: func() []byte {
				// Modbus Exception Response to an implicit Read Holding Registers
				// request (function code 0x03). Real Modbus devices that receive
				// a malformed or unsolicited connection often reply with an
				// exception frame. This is the fingerprint Shodan's "modbus" search uses.
				// Frame: transaction ID 0x0001, protocol 0x0000, length 0x0003,
				// unit ID 0x01, exception function 0x83, exception code 0x01 (illegal fn).
				return []byte{
					0x00, 0x01, // transaction identifier
					0x00, 0x00, // protocol identifier (0 = Modbus)
					0x00, 0x03, // length = 3 bytes follow
					0x01, // unit identifier
					0x83, // function code 0x03 | 0x80 (exception flag)
					0x01, // exception code: Illegal Function
				}
			},
		},
		serviceEntry{
			Port: 20000, // DNP3 (Distributed Network Protocol) — power/water SCADA
			Banner: func() []byte {
				// DNP3 Unsolicited Response frame — the "I'm alive" beacon that
				// real outstations (RTUs) send on new TCP connections.
				// Start bytes 0x0564, length, ctrl, dst 0xFFFF (broadcast),
				// src 0x0001, function 0x82 (Unsolicited Response), IIN bytes.
				return []byte{
					0x05, 0x64, // DNP3 start bytes
					0x14,       // length = 20
					0x44,       // control: DIR=0, PRM=1, FCB=0, FCV=0, FC=4 (Unsolicited Response)
					0xff, 0xff, // destination address (master broadcast)
					0x01, 0x00, // source address = 1
					0x00, 0x00, // CRC placeholder (real devices compute this)
					// Application layer
					0xc0,       // app control: FIR=1, FIN=1, CON=0, UNS=1, seq=0
					0x82,       // function code: Unsolicited Response
					0x80, 0x00, // IIN1=0x80 (device restart), IIN2=0x00
					0x00, 0x00, // CRC placeholder
				}
			},
		},
		serviceEntry{
			Port: 44818, // EtherNet/IP (CIP) — Rockwell/Allen-Bradley PLCs
			Banner: func() []byte {
				// EtherNet/IP List Identity reply — the response to a broadcast
				// "Who's there?" query. Rockwell scanners and Shodan's "ethernetip"
				// filter look for this exact 65-byte structure.
				// Command 0x0063, length 0x0035, session 0, status 0.
				return []byte{
					0x63, 0x00, // command: List Identity (0x0063) LE
					0x35, 0x00, // length = 53 bytes of data follow
					0x00, 0x00, 0x00, 0x00, // session handle
					0x00, 0x00, 0x00, 0x00, // status = success
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sender context
					0x00, 0x00, 0x00, 0x00, // options
					// CPF item: Identity Object
					0x01, 0x00, // item count = 1
					0x0c, 0x00, // item type: Identity Object (0x000c) LE
					0x2d, 0x00, // item length = 45
					0x01, 0x00, // encapsulation protocol version
					// socket address (sin_family=AF_INET, port=44818, addr=0)
					0x00, 0x02, 0xaf, 0x12, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x01, 0x00, // vendor ID: Rockwell Automation (1)
					0x02, 0x00, // device type: Communications Adapter (2)
					0x89, 0x00, // product code: 1756-ENBT (137)
					0x03, 0x05, // revision: 3.5
					0x30, 0x00, // status
					0x01, 0x02, 0x03, 0x04, // serial number
					// product name: "1756-ENBT/A" (len-prefixed)
					0x0b, '1', '7', '5', '6', '-', 'E', 'N', 'B', 'T', '/', 'A',
					0x03, // state: Operational
				}
			},
		},

		// ── Network Infrastructure ────────────────────────────────────────────
		serviceEntry{
			Port: 631, // IPP — Internet Printing Protocol (CUPS)
			Banner: func() []byte {
				// CUPS/IPP responds to any TCP connection with an HTTP 426 if it
				// receives non-HTTP, or a proper HTTP response to GET /.
				// We return a realistic CUPS server-info page header that scanners
				// see when probing for exposed print servers.
				body := `<!DOCTYPE HTML><html><head><title>Home - CUPS 2.4.2</title></head><body><h1>CUPS 2.4.2</h1></body></html>`
				return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
					"Content-Type: text/html; charset=utf-8\r\n"+
					"Content-Length: %d\r\n"+
					"Server: CUPS/2.4 IPP/2.1\r\n"+
					"X-Frame-Options: DENY\r\n"+
					"\r\n"+
					"%s", len(body), body))
			},
		},
		serviceEntry{
			Port: 2082, // cPanel HTTP (unencrypted)
			Banner: func() []byte {
				body := `<html><head><title>cPanel Login</title></head><body><h1>cPanel</h1></body></html>`
				return []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
					"Content-Type: text/html; charset=UTF-8\r\n"+
					"Content-Length: %d\r\n"+
					"Server: cpsrvd/11.112\r\n"+
					"X-CPanel-Version: 11.112\r\n"+
					"\r\n"+
					"%s", len(body), body))
			},
		},
		serviceEntry{
			Port: 2083, // cPanel HTTPS (TLS — we return TLS alert, same pattern as 443)
			Banner: func() []byte {
				return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
			},
		},
		serviceEntry{
			Port: 3283, // Apple Remote Desktop (ARD) / Net Assistant
			Banner: func() []byte {
				// ARD sends a 2-byte capability word immediately on connect.
				// 0x00 0x02 = "server supports authentication".
				// Scanners checking for exposed ARD look for this exact 2-byte response.
				return []byte{0x00, 0x02}
			},
		},
		serviceEntry{
			Port: 4899, // Radmin (Remote Administrator) — popular in Eastern Europe
			Banner: func() []byte {
				// Radmin v3 sends a 9-byte handshake: magic 0x52 0x46 0x42 ("RFB"
				// prefix used by Radmin), protocol version string.
				// Scanners look for this to find unpatched Radmin 2.x (auth bypass).
				return []byte("RFB 003.006\n")
			},
		},
		serviceEntry{
			Port: 5985, // WinRM HTTP (Windows Remote Management)
			Banner: func() []byte {
				// WinRM over HTTP returns a 401 with NTLM/Negotiate challenge
				// on the /wsman endpoint. This is what scanners expect to see.
				body := `<html><head><title>404 - Not Found</title></head><body>Not Found</body></html>`
				return []byte(fmt.Sprintf("HTTP/1.1 404 Not Found\r\n"+
					"Content-Type: text/html; charset=UTF-8\r\n"+
					"Content-Length: %d\r\n"+
					"Server: Microsoft-HTTPAPI/2.0\r\n"+
					"\r\n"+
					"%s", len(body), body))
			},
		},
		serviceEntry{
			Port: 5986, // WinRM HTTPS
			Banner: func() []byte {
				return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
			},
		},
		serviceEntry{
			Port: 8291, // MikroTik Winbox
			Banner: func() []byte {
				// Winbox protocol: client sends a probe, server responds with
				// a 4-byte length-prefixed packet. The magic first byte 0x01
				// followed by 0x00 0x00 0x00 is the Winbox "null session" banner
				// that all Winbox port scanners (and the VPNFilter malware) look for.
				return []byte{0x01, 0x00, 0x00, 0x00}
			},
		},
		serviceEntry{
			Port: 8728, // MikroTik RouterOS API (plaintext)
			Banner: func() []byte {
				// RouterOS API uses a length-prefixed sentence protocol.
				// On connect, the router sends its version sentence:
				// !done followed by =ret=<version>.
				// Each word is length-prefixed with a 1-byte length.
				// This is the exact greeting a real RouterOS 6.x/7.x device sends.
				sentence := func(words ...string) []byte {
					var b []byte
					for _, w := range words {
						b = append(b, byte(len(w)))
						b = append(b, []byte(w)...)
					}
					b = append(b, 0x00) // end of sentence
					return b
				}
				return sentence("!done", "=ret=ROS_7.14")
			},
		},
		serviceEntry{
			Port: 8729, // MikroTik RouterOS API-SSL
			Banner: func() []byte {
				return []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}
			},
		},
	)
}

// udpServicePorts are the UDP ports webTraffik captures.
var udpServicePorts = []int{
	53,    // DNS
	123,   // NTP
	161,   // SNMP
	1434,  // MSSQL Browser/Monitor
	1900,  // SSDP/UPnP
	5060,  // SIP
	30303, // Ethereum P2P (devp2p discovery)
	47808, // BACnet (building automation)
}
