# SERVICES.md — webTraffik Service Emulation Reference

This document provides a detailed reference of every service webTraffik emulates. When a connection is received on one of these ports, webTraffik logs it, geolocates the source IP, and (for TCP services) sends back a convincing protocol-specific banner designed to fingerprint as the real service to scanners and bots.

**Source of truth**: All service definitions live in `services.go`. This document reflects the current state of that file.

---

## TCP Service Emulations

webTraffik binds raw TCP listeners (using `net.Listen`, not HTTP) on the following ports. When a connection is accepted:

1. The source IP and port are captured and logged
2. A geolocation event is fired and streamed to connected dashboards
3. The service-specific banner bytes are sent immediately to the client
4. The connection is closed

This creates realistic fingerprints that scanners and reconnaissance tools will recognize as real services, making webTraffik an effective honeypot.

### TCP Services Table

| Port | Service | Protocol | Banner Summary |
|------|---------|----------|----------------|
| 21 | FTP | File Transfer Protocol | `220 FTP Server ready.` — standard FTP greeting |
| 22 | SSH | Secure Shell | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` — mimics OpenSSH version string |
| 23 | Telnet | Telnet | IAC DO TERMINAL-TYPE + IAC DO NAWS negotiation bytes + `Login: ` prompt |
| 25 | SMTP | Simple Mail Transfer Protocol | `220 mail.example.com ESMTP Postfix (Ubuntu)` — mimics Postfix MTA |
| 110 | POP3 | Post Office Protocol 3 | `+OK POP3 server ready` — standard POP3 greeting |
| 143 | IMAP | Internet Message Access Protocol | `* OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.` — mimics Dovecot IMAP |
| 443 | HTTPS | HTTP over TLS | TLS 1.0 Alert (fatal, handshake_failure) — realistic response to ClientHello |
| 445 | SMB | Server Message Block | Minimal SMB2 NEGOTIATE response with STATUS_NOT_SUPPORTED — fingerprints as Windows SMB |
| 1433 | MSSQL | Microsoft SQL Server | TDS pre-login response indicating version 15.00.2000, encryption not supported |
| 3306 | MySQL | MySQL Database | MySQL 8.0.35 handshake packet (Protocol 10) with caching_sha2_password |
| 3389 | RDP | Remote Desktop Protocol | X.224 Connection Confirm PDU with RDP_NEG_RSP (PROTOCOL_RDP, no enhanced security) |
| 5432 | PostgreSQL | PostgreSQL Database | ErrorResponse: `FATAL: no pg_hba.conf entry for host` — realistic rejection |
| 6379 | Redis | Redis In-Memory Database | `-DENIED Redis is running in protected mode` — mimics Redis protected mode |
| 27017 | MongoDB | MongoDB Database | OP_REPLY with BSON `{ok:0, errmsg:"Authentication required", code:13}` |
| 5900 | VNC | Virtual Network Computing | `RFB 003.008\n` — RFB protocol version handshake for VNC 3.8 |
| 8443 | HTTPS-Alt | HTTP over TLS (alternate port) | Same TLS handshake_failure alert as port 443 |
| 9200 | Elasticsearch | Elasticsearch Search Engine | HTTP 200 with JSON body mimicking Elasticsearch 7.17.16 node info |
| 11211 | Memcached | Memcached In-Memory Cache | `ERROR\r\n` — memcached text protocol error response |

### Detailed Service Descriptions

#### Port 21 — FTP (File Transfer Protocol)

**Banner**: `220 FTP Server ready.\r\n`

**Purpose**: Standard FTP server greeting. The `220` code indicates "Service ready for new user." This is what legitimate FTP clients expect to see when connecting.

**Why it's convincing**: All FTP servers send a 220 greeting line. Scanners looking for open FTP servers will recognize this as a valid FTP endpoint.

---

#### Port 22 — SSH (Secure Shell)

**Banner**: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n`

**Purpose**: SSH protocol version string identifying the server as OpenSSH 8.9p1 running on Ubuntu.

**Why it's convincing**: Every SSH server sends its version string as the first line upon connection. This particular version string matches a real Ubuntu 22.04 LTS OpenSSH package, making it indistinguishable from a real SSH server to automated scanners.

---

#### Port 23 — Telnet

**Banner**: `\xff\xfd\x18\xff\xfd\x1f\r\nLogin: `

**Purpose**: Telnet IAC (Interpret As Command) negotiation bytes followed by a login prompt.
- `\xff\xfd\x18` = IAC DO TERMINAL-TYPE (asks client to send terminal type)
- `\xff\xfd\x1f` = IAC DO NAWS (Negotiate About Window Size)

**Why it's convincing**: Real telnet servers negotiate terminal capabilities using IAC commands before presenting a login prompt. This minimal negotiation is enough to fingerprint as a telnet service.

---

#### Port 25 — SMTP (Simple Mail Transfer Protocol)

**Banner**: `220 mail.example.com ESMTP Postfix (Ubuntu)\r\n`

**Purpose**: SMTP greeting identifying the server as a Postfix MTA (Mail Transfer Agent) on Ubuntu.

**Why it's convincing**: The `220` code is the standard SMTP "Service ready" response. Postfix is one of the most common MTAs on Linux servers, and this banner format matches real Postfix installations exactly.

---

#### Port 110 — POP3 (Post Office Protocol 3)

**Banner**: `+OK POP3 server ready\r\n`

**Purpose**: Standard POP3 greeting line.

**Why it's convincing**: All POP3 servers send a `+OK` greeting. This is the minimal valid response that clients and scanners expect.

---

#### Port 143 — IMAP (Internet Message Access Protocol)

**Banner**: `* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS AUTH=PLAIN] Dovecot ready.\r\n`

**Purpose**: IMAP greeting with a full capability advertisement identifying the server as Dovecot (a popular IMAP server).

**Why it's convincing**: The capability list includes common IMAP extensions (IDLE, STARTTLS, AUTH=PLAIN) that real Dovecot servers advertise. Scanners looking for IMAP servers will see this as a fully-featured mail server.

---

#### Port 443 — HTTPS (HTTP over TLS)

**Banner**: `\x15\x03\x01\x00\x02\x02\x28` (TLS Alert Record)

**Purpose**: TLS 1.0 alert message indicating a fatal handshake failure.
- `\x15` = content type 21 (alert)
- `\x03\x01` = TLS version 1.0
- `\x00\x02` = length 2
- `\x02` = alert level 2 (fatal)
- `\x28` = alert description 40 (handshake_failure)

**Why it's convincing**: When a client sends a TLS ClientHello to initiate a secure connection, a real server that cannot complete the handshake (e.g., due to cipher mismatch or missing certificates) sends a TLS alert. This response looks like a real HTTPS server that rejected the connection for a valid cryptographic reason, rather than a closed port or non-TLS service.

---

#### Port 445 — SMB (Server Message Block)

**Banner**: Minimal SMB2 NEGOTIATE response (84 bytes)

**Purpose**: NetBIOS Session Service header + SMB2 magic bytes (`\xFE\x53\x4D\x42`) + error code STATUS_NOT_SUPPORTED.

**Why it's convincing**: Windows file sharing uses SMB/SMB2. Scanners (like those used by ransomware and worms looking for EternalBlue vulnerabilities) send SMB NEGOTIATE packets to fingerprint Windows systems. This response identifies the host as a Windows SMB server that received the request but does not support the requested operation — enough to register as a real SMB endpoint without implementing the full protocol.

---

#### Port 1433 — MSSQL (Microsoft SQL Server)

**Banner**: TDS (Tabular Data Stream) pre-login response (37 bytes)

**Purpose**: Indicates server version 15.00.2000 (SQL Server 2019) with encryption not supported.

**Why it's convincing**: Microsoft SQL Server uses the TDS protocol. The pre-login handshake is the first packet exchange in the connection flow. This response advertises a realistic server version and encryption status, enough to fingerprint as MSSQL to database scanners.

---

#### Port 3306 — MySQL

**Banner**: MySQL Protocol 10 handshake packet (81 bytes)

**Purpose**: Advertises MySQL 8.0.35 with caching_sha2_password authentication plugin.

**Why it's convincing**: Every MySQL connection starts with a handshake packet containing:
- Protocol version (10)
- Server version string
- Connection ID
- Auth plugin data (challenge salt)
- Capability flags
- Auth plugin name

This is a complete, valid MySQL handshake that clients will recognize as MySQL 8.

---

#### Port 3389 — RDP (Remote Desktop Protocol)

**Banner**: X.224 Connection Confirm PDU (19 bytes)

**Purpose**: Indicates successful X.224 connection with RDP negotiation response selecting PROTOCOL_RDP (no enhanced security).

**Why it's convincing**: RDP uses the X.224 protocol for connection setup. This is the standard response to an RDP connection request. Scanners looking for exposed RDP servers will see this as a valid RDP endpoint.

---

#### Port 5432 — PostgreSQL

**Banner**: PostgreSQL ErrorResponse message

**Purpose**: Sends a FATAL error indicating "no pg_hba.conf entry for host" — the error PostgreSQL sends when a client IP is not allowed to connect.

**Why it's convincing**: Real PostgreSQL servers with restrictive `pg_hba.conf` files send this exact error to unauthorized clients. It fingerprints as a real Postgres server with security enabled.

---

#### Port 6379 — Redis

**Banner**: `-DENIED Redis is running in protected mode\r\n`

**Purpose**: Redis inline protocol error response.

**Why it's convincing**: Redis 3.2+ runs in "protected mode" by default when no password is set and it's not bound to localhost. This is the exact error message Redis sends to external clients in that configuration. Scanners will recognize this as a real Redis instance with default security settings.

---

#### Port 27017 — MongoDB

**Banner**: MongoDB OP_REPLY wire protocol message with BSON error document

**Purpose**: Sends a BSON document `{ok: 0.0, errmsg: "Authentication required", code: 13}` indicating authentication is required.

**Why it's convincing**: MongoDB uses a binary wire protocol. This is a valid OP_REPLY message with an error document — exactly what MongoDB sends when authentication is enabled and the client has not authenticated. Scanners looking for open MongoDB instances will see this as a real MongoDB server with auth enabled.

---

#### Port 5900 — VNC (Virtual Network Computing)

**Banner**: `RFB 003.008\n`

**Purpose**: RFB (Remote Framebuffer) protocol version handshake for VNC 3.8.

**Why it's convincing**: All VNC servers start by announcing their RFB protocol version. This is the standard greeting for VNC 3.8 (the most widely supported version). Scanners will recognize this as a real VNC server.

---

#### Port 8443 — HTTPS-Alt (HTTP over TLS, alternate port)

**Banner**: Same TLS alert as port 443 (`\x15\x03\x01\x00\x02\x02\x28`)

**Purpose**: Port 8443 is a common alternate HTTPS port (used by Tomcat, application servers, control panels). Sends the same TLS handshake_failure alert as port 443.

**Why it's convincing**: See port 443 description. This port catches scanners looking for HTTPS on non-standard ports.

---

#### Port 9200 — Elasticsearch

**Banner**: HTTP 200 response with JSON body:

```json
{
  "name" : "node-1",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "7.17.16",
    "build_flavor" : "default",
    "lucene_version" : "8.11.1",
    ...
  },
  "tagline" : "You Know, for Search"
}
```

**Purpose**: Mimics the response to `GET /` on an Elasticsearch node.

**Why it's convincing**: This is the exact JSON structure Elasticsearch returns on its root endpoint. Scanners looking for exposed Elasticsearch instances (common targets due to data exposure risks) will see this as a real Elasticsearch 7.17.16 node.

---

#### Port 11211 — Memcached

**Banner**: `ERROR\r\n`

**Purpose**: Memcached text protocol error response.

**Why it's convincing**: Scanners typically send `stats\r\n` or `version\r\n` commands to fingerprint memcached. Responding with `ERROR` is a valid memcached response indicating the command was not understood or not allowed. This is enough to fingerprint as memcached without implementing the full protocol.

---

## Minecraft Java Edition (Port 25565)

**Port 25565** is handled differently from the banner-based services above. webTraffik implements a full **Server List Ping** protocol emulation as defined in the [Minecraft protocol specification](https://wiki.vg/Server_List_Ping).

### Protocol Flow

1. **Client → Server**: Handshake packet (VarInt-framed, packet ID 0x00, next_state=1)
2. **Client → Server**: Status Request (packet ID 0x00, empty payload)
3. **Server → Client**: Status Response (packet ID 0x00, JSON payload describing the server)
4. **Client → Server** (optional): Ping Request (packet ID 0x01, 8-byte payload)
5. **Server → Client** (optional): Pong Response (packet ID 0x01, echo same 8 bytes)

### Advertised Server Details

```json
{
  "version": {
    "name": "1.20.4",
    "protocol": 765
  },
  "players": {
    "max": 20,
    "online": 3,
    "sample": []
  },
  "description": {
    "text": "A Minecraft Server"
  }
}
```

### Why it's convincing

Minecraft clients query servers using the Server List Ping protocol to display server info in the multiplayer browser (version, player count, MOTD). webTraffik's implementation responds exactly as a real Minecraft 1.20.4 server would, making the server appear in Minecraft client server lists as a real online server.

This catches:
- Minecraft scanners and bots
- Players manually adding the IP to their server list
- Automated services that index public Minecraft servers

---

## HTTP Capture Ports

The following ports run plain HTTP listeners (using `http.ListenAndServe` from Go's `net/http` package). These are **not** service emulations — they simply accept the HTTP request, log the connection, and return an empty HTTP 200 response with no body.

**Ports**: 80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, 3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090

### Service Name Mapping (used in UI)

These mappings are defined in `services.go:portServiceName()` and displayed in the dashboard:

| Port(s) | Service Name | Common Use Cases |
|---------|--------------|------------------|
| 80 | HTTP | Standard HTTP |
| 8080, 8000, 8008, 8081, 8088, 8090, 8888 | HTTP-Alt | Alternate HTTP ports, proxies, Tomcat, Jenkins |
| 3000, 3001 | Node/Dev | Node.js/Express, Grafana, Rails, React dev server |
| 3128 | Proxy | Squid proxy default port |
| 4000 | Phoenix | Phoenix (Elixir framework) dev server |
| 4200 | Angular | Angular CLI dev server |
| 5000, 5001 | Flask/Dev | Flask dev server, Docker Registry API |
| 9000 | SonarQube | SonarQube, Portainer |
| 9090 | Prometheus | Prometheus metrics server, Cockpit |

**Why these ports**: These are common ports targeted by web vulnerability scanners looking for exposed dev servers, proxies, CI/CD systems, and application frameworks.

---

## UDP Capture Ports

webTraffik binds UDP listeners (using `net.ListenPacket`) on the following ports. When a datagram is received:

1. The source IP and port are captured
2. A geolocation event is fired and streamed to dashboards
3. **No response is sent** — the datagram is silently discarded

This is intentional: many UDP-based reconnaissance and amplification attacks rely on responses. By capturing without responding, webTraffik logs the activity without participating in reflection attacks.

| Port | Service | Protocol |
|------|---------|----------|
| 53 | DNS | Domain Name System |
| 123 | NTP | Network Time Protocol |
| 161 | SNMP | Simple Network Management Protocol |
| 1900 | SSDP/UPnP | Simple Service Discovery Protocol / Universal Plug and Play |
| 5060 | SIP | Session Initiation Protocol (VoIP) |

**Why these ports**:
- **DNS (53)**: Used by DNS amplification attacks and reconnaissance
- **NTP (123)**: Target of NTP amplification DDoS attacks
- **SNMP (161)**: Common target for device enumeration and exploitation
- **SSDP (1900)**: Used by UPnP exploits and device discovery scans
- **SIP (5060)**: VoIP service discovery and SIP scanning

---

## Maintenance

**IMPORTANT**: This file must stay in sync with `services.go`.

When adding, removing, or modifying a service in `services.go`:

1. **Update this file** (`SERVICES.md`) with the new service's port, protocol, banner details, and purpose
2. **Update `firewall.sh`**:
   - Add the port to `CAPTURE_PORTS_TCP` (for TCP services) or `CAPTURE_PORTS_UDP` (for UDP services)
3. **Update `AGENTS.md`**: If this is a new service category or changes the port count, update the architecture section
4. **Rebuild and redeploy**: `make remote-install IP=x.x.x.x`

The port lists in `firewall.sh` must always match the port lists in `services.go` and `main.go` to ensure the firewall exposes exactly the ports the app is listening on.

---

**Last synchronized with**: `services.go` as of the current codebase state (18 TCP services, 5 UDP services, 1 Minecraft service, 17 HTTP ports)
