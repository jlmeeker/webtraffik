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
| 135 | RPC | Microsoft DCE/RPC Endpoint Mapper | DCE/RPC bind_nak rejection (LOCAL_LIMIT_EXCEEDED) |
| 139 | NetBIOS | NetBIOS Session Service | Negative session response (not listening on called name) |
| 143 | IMAP | Internet Message Access Protocol | `* OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.` — mimics Dovecot IMAP |
| 443 | HTTPS | HTTP over TLS | TLS 1.0 Alert (fatal, handshake_failure) — realistic response to ClientHello |
| 445 | SMB | Server Message Block | Minimal SMB2 NEGOTIATE response with STATUS_NOT_SUPPORTED — fingerprints as Windows SMB |
| 554 | RTSP | Real Time Streaming Protocol | `RTSP/1.0 200 OK` with CSeq, Public methods, and Server: GStreamer RTSP Server headers |
| 993 | IMAPS | IMAP over SSL/TLS | TLS handshake_failure alert (same as port 443) |
| 995 | POP3S | POP3 over SSL/TLS | TLS handshake_failure alert (same as port 443) |
| 1433 | MSSQL | Microsoft SQL Server | TDS pre-login response indicating version 15.00.2000, encryption not supported |
| 1521 | Oracle | Oracle Database TNS Listener | TNS Refuse packet with error code 1153 |
| 1723 | PPTP | Point-to-Point Tunneling Protocol VPN | PPTP Start-Control-Connection-Reply (156 bytes) |
| 2375 | Docker | Docker Daemon REST API (unencrypted) | HTTP 200 OK mimicking Docker's `/_ping` endpoint with Api-Version and Docker headers |
| 3306 | MySQL | MySQL Database | MySQL 8.0.35 handshake packet (Protocol 10) with caching_sha2_password |
| 3333 | Stratum | Cryptocurrency Mining Pool Protocol | JSON-RPC mining.notify notification — mimics mining pool distributing work |
| 3389 | RDP | Remote Desktop Protocol | X.224 Connection Confirm PDU with RDP_NEG_RSP (PROTOCOL_RDP, no enhanced security) |
| 4444 | Metasploit | Metasploit Default Reverse Shell | No banner (silent accept) |
| 5432 | PostgreSQL | PostgreSQL Database | ErrorResponse: `FATAL: no pg_hba.conf entry for host` — realistic rejection |
| 5555 | ADB | Android Debug Bridge | ADB CNXN connect response with device identity string |
| 5900 | VNC | Virtual Network Computing | `RFB 003.008\n` — RFB protocol version handshake for VNC 3.8 |
| 6000 | X11 | X Window System | X11 connection-refused response with "No protocol specified" error |
| 6379 | Redis | Redis In-Memory Database | `-DENIED Redis is running in protected mode` — mimics Redis protected mode |
| 6667 | IRC | Internet Relay Chat | IRC NOTICE AUTH hostname lookup messages |
| 8333 | Bitcoin | Bitcoin P2P Network (mainnet) | Bitcoin protocol version message (magic 0xF9BEB4D9, version 70016, /Satoshi:25.0.0/) |
| 8443 | HTTPS-Alt | HTTP over TLS (alternate port) | Same TLS handshake_failure alert as port 443 |
| 8545 | Ethereum-RPC | Ethereum JSON-RPC HTTP Endpoint | HTTP 200 with JSON-RPC error {"code":-32600,"message":"Invalid Request"} |
| 8546 | Ethereum-WS | Ethereum WebSocket JSON-RPC Endpoint | HTTP 426 Upgrade Required — geth WebSocket endpoint response |
| 9100 | Printer | HP JetDirect / Printer Services | PJL INFO STATUS "Ready" response |
| 9200 | Elasticsearch | Elasticsearch Search Engine | HTTP 200 with JSON body mimicking Elasticsearch 7.17.16 node info |
| 9735 | Lightning | Lightning Network P2P (BOLT #8) | 50-byte Act One response (Noise_XK handshake) |
| 10009 | Lightning-gRPC | Lightning Network lnd gRPC API | HTTP/2 SETTINGS frame (server connection preface) |
| 11211 | Memcached | Memcached In-Memory Cache | `ERROR\r\n` — memcached text protocol error response |
| 18080 | Monero-P2P | Monero P2P Network (monerod) | Levin protocol header with signature 0x0121010101010101 and handshake command |
| 18081 | Monero-RPC | Monero JSON-RPC Endpoint (monerod) | HTTP 200 with JSON-RPC error — standard Monero RPC error response |
| 18789 | OpenClaw | OpenClaw AI Assistant Gateway | HTTP 426 Upgrade Required with WebSocket upgrade headers |
| 27017 | MongoDB | MongoDB Database | OP_REPLY with BSON `{ok:0, errmsg:"Authentication required", code:13}` |
| 30303 | Ethereum-P2P | Ethereum P2P Network (devp2p/RLPx) | No banner (connection accept only) — waits for initiator's encrypted auth message |

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

#### Port 135 — RPC (Microsoft DCE/RPC Endpoint Mapper)

**Banner**: DCE/RPC bind_nak (bind rejection) response

**Purpose**: Sends a minimal DCE/RPC bind_nak packet with reject reason `LOCAL_LIMIT_EXCEEDED` (0x03). This is the response a Windows RPC Endpoint Mapper service sends when refusing a connection due to resource limits or policy restrictions.

**Why it's convincing**: Port 135 is the Microsoft RPC Endpoint Mapper, a critical Windows networking service. The DCE/RPC bind_nak packet format matches exactly what a real Windows RPC service returns when rejecting a connection attempt. Scanners looking for Windows hosts or RPC services will recognize this as a legitimate Windows system.

**Why this port is targeted**: Port 135 is heavily scanned by:
- **Mirai variants and IoT botnets** looking for Windows devices to compromise
- **Worm propagation tools** (Conficker, WannaCry lateral movement) that use RPC for network enumeration
- **Network reconnaissance tools** mapping Windows infrastructure
- **Exploit scanners** looking for vulnerable RPC services (MS03-026, MS03-039, MS08-067)

Windows RPC is a foundational service for Windows networking and is one of the most-scanned ports on the internet for Windows host discovery and exploitation.

---

#### Port 139 — NetBIOS (NetBIOS Session Service)

**Banner**: NetBIOS negative session response (type 0x83)

**Purpose**: Sends a NetBIOS Session Service negative response with error code 0x80 ("Not listening on called name"). This is what a Windows system sends when it receives a NetBIOS session request but is not listening on the requested NetBIOS name.

**Why it's convincing**: Port 139 is the NetBIOS Session Service, used by older Windows systems for file sharing (before SMB direct hosting on port 445). The negative session response is a valid NetBIOS packet that fingerprints as a Windows system. Scanners will see this as a real NetBIOS endpoint.

**Why this port is targeted**: Port 139 is scanned alongside port 445 (SMB) for:
- **Windows network reconnaissance** — attackers probe both 139 and 445 together to map Windows file sharing services
- **Lateral movement** — ransomware and worms use NetBIOS for network propagation
- **Share enumeration** — attackers attempt to list and access network shares
- **Credential harvesting** — brute-force attacks against Windows authentication

While port 445 has largely replaced 139 for SMB, many scanners still target both ports as part of Windows infrastructure mapping.

---

#### Port 554 — RTSP (Real Time Streaming Protocol)

**Banner**: `RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\nServer: GStreamer RTSP Server\r\n\r\n`

**Purpose**: Sends a standard RTSP 200 OK response listing supported methods. This is the response an RTSP media server (IP camera, media streaming server) sends when queried. The response includes:
- Status line: `RTSP/1.0 200 OK` indicating successful request processing
- CSeq header: matches the client's command sequence number
- Public header: lists supported RTSP methods (DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE)
- Server header: identifies as GStreamer RTSP Server, a common media framework used in IP camera firmware

**Why it's convincing**: RTSP servers respond to OPTIONS requests (and some malformed requests) with a 200 OK listing supported methods. The GStreamer server string is ubiquitous in IP camera firmware (Hikvision, Dahua, Axis, and countless OEM/white-label cameras use GStreamer). Scanners and Shodan recognize this as a real RTSP endpoint.

**Why this port is targeted**: Port 554 is one of the most heavily scanned IoT ports on the internet:
- **IP camera exploitation** — the Mirai botnet and its variants (Satori, Okiru, Masuta) specifically target RTSP-enabled cameras for compromise and recruitment into DDoS botnets
- **Surveillance infrastructure mapping** — attackers and intelligence agencies scan for exposed security cameras to map physical surveillance coverage, identify facility locations, and gather intelligence
- **Default credential brute-forcing** — most IP cameras ship with default credentials (admin/admin, admin/12345, root/pass), and RTSP endpoints are primary targets for credential stuffing attacks
- **RTSP stream hijacking** — attackers access live video feeds to eavesdrop on private spaces (homes, businesses, government facilities)
- **Video feed enumeration** — Shodan and Censys actively index exposed RTSP streams, and numerous "Insecam"-style websites aggregate and publish unsecured camera feeds
- **Vulnerability exploitation** — RTSP implementations in cheap IP cameras are riddled with buffer overflows, authentication bypasses (CVE-2017-7921, CVE-2018-9995), and remote code execution vulnerabilities
- **Ransomware targeting** — surveillance systems are increasingly targeted by ransomware due to the high-value nature of video footage (evidence in legal cases, safety monitoring, etc.)

Port 554 represents one of the largest attack surfaces in the IoT ecosystem — exposed RTSP cameras are pervasive, poorly secured, and provide both network access and real-world surveillance capabilities to attackers.

---

#### Port 5900 — VNC (Virtual Network Computing)

**Protocol Flow**: Partial RFB handshake with tarpit behavior (anti-brute-force behavior)

VNC implements the initial RFB protocol version exchange and then applies a tarpit strategy to slow down repeat scanners:

1. **Server → Client**: Protocol version — `RFB 003.008\n` (VNC 3.8)
2. **Client → Server**: Client version string (12 bytes) — **captured as client data**
3. **Server behavior**:
   - **First connection from an IP**: Close silently after version exchange
   - **Repeat connections from the same IP within 60 seconds**: After version exchange, hold the connection open for a random 10–30 seconds before closing silently

**Tarpit mechanism**: When a scanner connects repeatedly from the same source IP within a 60-second window, the connection is held open (after the version exchange is complete and captured) for a random 10–30 second duration. This ties up a thread or connection slot in the scanner's connection pool, significantly throttling their scan rate without signaling anything unusual to the scanner. The held connection appears to the scanner as a slow network or unresponsive endpoint rather than active defense, making it less likely to trigger evasion tactics or alert the attacker.

**Per-IP tracking**: The service maintains a map of recently-seen source IPs. This map is automatically pruned every 5 minutes to prevent unbounded memory growth during sustained high-volume scans.

**Purpose**: Captures VNC reconnaissance traffic while actively slowing down brute-force and mass-scanning operations. The tarpit strategy punishes repeat offenders by consuming their scanning resources without alerting them to defensive behavior.

**Why it's convincing**: All VNC servers start by announcing their RFB protocol version (3.8 is the most widely supported). The version exchange is enough to fingerprint as a real VNC server to reconnaissance scanners and initial connection attempts. The silent close (first connection) or slow response (repeat connections) mimics network latency or an overloaded VNC server rather than active filtering, keeping the deception intact.

**Why this behavior**: A silent drop after version exchange (before security negotiation) looks like a network error or firewall reset to automated scanners, causing most brute-force bots to back off. For persistent scanners that retry, the tarpit delay consumes their connection pool slots and dramatically slows their scan rate across the entire internet, protecting not just this host but reducing their overall threat capacity. By contrast, sending a proper SecurityResult:failed response (the old behavior) looks identical to a real VNC server rejecting a bad password, which signals brute-force bots that authentication is present and encourages them to retry indefinitely.

---

#### Port 6000 — X11 (X Window System)

**Banner**: X11 connection-refused response (binary protocol)

**Purpose**: Sends the exact binary response an X11 server (Xorg, XFree86) returns when refusing a client connection due to authentication failure:

```
0x00 (Failed)
0x0B (reason-length in bytes)
0x00 0x0B (protocol major version 11)
0x00 0x00 (protocol minor version 0)
0x00 0x03 (additional data length in 4-byte units)
"No protocol specified" (11 bytes, padded to 12 bytes with null for 4-byte alignment)
```

The response structure is:
- Status byte: 0x00 (Failed) — indicates connection refused
- Reason length: length of the error message string
- Protocol version: 11.0 (X Window System version 11)
- Additional data length: length of remaining data in 4-byte units
- Reason string: "No protocol specified" — the standard Xorg error when xhost restrictions deny the client

**Why it's convincing**: This is the exact binary response an X11 server sends when refusing a connection due to authentication failure. The "No protocol specified" error is the most common rejection message from Xorg/XFree86 when the DISPLAY environment variable is not authorized via xhost or xauth. Scanners looking for exposed X11 servers will recognize this as a real X server with access control enabled (but the mere fact that port 6000 is open and responding with valid X11 protocol is enough to fingerprint the host as running X Window System).

**Why this port is targeted**: Port 6000 (and sequential ports 6001, 6002, etc. for multiple X displays) represents a critical security vulnerability when exposed to networks:
- **X11 keylogging and screen capture** — an open X server allows remote keylogging and screenshot capture WITHOUT ANY EXPLOIT. The X protocol's design allows any connected client to read keyboard input and screen contents from all windows. This is not a vulnerability — it's a feature of the X Window System's network transparency.
- **Clipboard access** — attackers can read and write the X clipboard, capturing passwords, API keys, and sensitive data copied by users
- **Window manipulation** — attackers can inject keyboard and mouse events into applications, effectively remote-controlling the desktop session
- **Credential harvesting** — by capturing keystrokes and screenshots, attackers can harvest login credentials, API tokens, SSH keys, and other sensitive information
- **Session hijacking** — complete desktop session takeover is possible without authentication if xhost is misconfigured (`xhost +` grants access to any client)
- **Lateral movement** — compromised X sessions provide access to the user's files, shell history, SSH agent sockets, and can be used to pivot to other systems
- **Privilege escalation** — if the X session is running as root (rare but not unheard of in legacy systems), attackers gain root-equivalent access

While X11 forwarding over SSH is less common now (Wayland is gradually replacing X11 in modern Linux distributions), legacy systems, remote workstations, and misconfigured lab/development machines still expose X11 ports. Shodan indexes thousands of open X11 servers, and attackers actively scan for them as high-value targets for credential theft and lateral movement.

The combination of network exposure + powerful remote capabilities + weak authentication (xhost-based) makes port 6000 one of the most dangerous ports to expose on a workstation or desktop system.

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

**Protocol Flow**: Partial RFB handshake with tarpit behavior (anti-brute-force behavior)

VNC implements the initial RFB protocol version exchange and then applies a tarpit strategy to slow down repeat scanners:

1. **Server → Client**: Protocol version — `RFB 003.008\n` (VNC 3.8)
2. **Client → Server**: Client version string (12 bytes) — **captured as client data**
3. **Server behavior**:
   - **First connection from an IP**: Close silently after version exchange
   - **Repeat connections from the same IP within 60 seconds**: After version exchange, hold the connection open for a random 10–30 seconds before closing silently

**Tarpit mechanism**: When a scanner connects repeatedly from the same source IP within a 60-second window, the connection is held open (after the version exchange is complete and captured) for a random 10–30 second duration. This ties up a thread or connection slot in the scanner's connection pool, significantly throttling their scan rate without signaling anything unusual to the scanner. The held connection appears to the scanner as a slow network or unresponsive endpoint rather than active defense, making it less likely to trigger evasion tactics or alert the attacker.

**Per-IP tracking**: The service maintains a map of recently-seen source IPs. This map is automatically pruned every 5 minutes to prevent unbounded memory growth during sustained high-volume scans.

**Purpose**: Captures VNC reconnaissance traffic while actively slowing down brute-force and mass-scanning operations. The tarpit strategy punishes repeat offenders by consuming their scanning resources without alerting them to defensive behavior.

**Why it's convincing**: All VNC servers start by announcing their RFB protocol version (3.8 is the most widely supported). The version exchange is enough to fingerprint as a real VNC server to reconnaissance scanners and initial connection attempts. The silent close (first connection) or slow response (repeat connections) mimics network latency or an overloaded VNC server rather than active filtering, keeping the deception intact.

**Why this behavior**: A silent drop after version exchange (before security negotiation) looks like a network error or firewall reset to automated scanners, causing most brute-force bots to back off. For persistent scanners that retry, the tarpit delay consumes their connection pool slots and dramatically slows their scan rate across the entire internet, protecting not just this host but reducing their overall threat capacity. By contrast, sending a proper SecurityResult:failed response (the old behavior) looks identical to a real VNC server rejecting a bad password, which signals brute-force bots that authentication is present and encourages them to retry indefinitely.

---

#### Port 6667 — IRC (Internet Relay Chat)

**Banner**: Standard IRC server NOTICE AUTH sequence

**Purpose**: Sends the IRC server greeting sequence that clients receive when connecting:
```
:irc.localhost NOTICE AUTH :*** Looking up your hostname...
:irc.localhost NOTICE AUTH :*** Checking Ident
:irc.localhost NOTICE AUTH :*** Found your hostname
```

This is the exact message sequence that IRC servers (ircd-hybrid, UnrealIRCd, InspIRCd, etc.) send during the connection initialization phase before user registration.

**Why it's convincing**: The NOTICE AUTH messages are the universal IRC server greeting pattern. Every IRC daemon sends hostname lookup and ident check notices in this format. Scanners and IRC clients will recognize this as a real IRC server.

**Why this port is targeted**: Port 6667 is heavily scanned by:
- **Botnet C&C reconnaissance** — IRC has historically been used as a command-and-control channel for botnets (Agobot, SDBot, etc.)
- **Open relay scanning** — attackers look for misconfigured IRC servers to abuse for spam or DDoS coordination
- **Vulnerability scanning** — multiple IRC daemon exploits exist (UnrealIRCd backdoor, ircd-hybrid overflows)
- **Network reconnaissance** — IRC servers often indicate informal or legacy infrastructure that may have other security weaknesses

While IRC usage has declined, it remains a target for botnet operators and attackers looking for communication channels.

---

#### Port 2375 — Docker (Docker Daemon REST API, unencrypted)

**Banner**: HTTP 200 OK response mimicking Docker's `/_ping` endpoint:

```
HTTP/1.1 200 OK\r\n
Api-Version: 1.45\r\n
Docker-Experimental: false\r\n
Ostype: linux\r\n
Server: Docker/25.0.3 (linux)\r\n
Content-Type: text/plain; charset=utf-8\r\n
Content-Length: 2\r\n
\r\n
OK
```

**Purpose**: Sends the exact response that Docker Engine's HTTP API returns for the `/_ping` health check endpoint. The response includes:
- Api-Version header: 1.45 (Docker Engine API version)
- Docker-Experimental header: false (stable release)
- Ostype header: linux (host OS)
- Server header: Docker/25.0.3 (linux) — recent Docker Engine version
- Body: "OK" (simple health check response)

**Why it's convincing**: This is byte-for-byte identical to what Docker Engine returns when the Docker daemon is exposed over TCP (via `dockerd -H tcp://0.0.0.0:2375` or `"hosts": ["tcp://0.0.0.0:2375"]` in daemon.json). Scanners looking for exposed Docker APIs check the `/_ping` endpoint first to confirm Docker presence before attempting more invasive operations. The Api-Version and Server headers match Docker Engine 25.0.3, a recent stable release.

**Why this port is targeted**: Port 2375 represents one of the most CATASTROPHIC misconfigurations in cloud and container infrastructure:
- **Complete host compromise** — an exposed Docker API grants the attacker full control over all containers AND the underlying host. Attackers can create privileged containers (`--privileged`), mount the host filesystem (`-v /:/host`), escape to the host via `chroot /host`, and execute arbitrary commands with root privileges.
- **Cryptominer deployment** — multiple botnet campaigns (TeamTNT, Kinsing, Doki, Hildegard, Siloscape) actively scan for port 2375 and immediately deploy cryptominers in privileged containers. TeamTNT alone infected thousands of Docker hosts and Kubernetes clusters.
- **Data exfiltration** — attackers can mount host volumes, access application secrets, database credentials, SSH keys, cloud provider credentials (AWS keys in `~/.aws`, GCP credentials, Azure tokens), and exfiltrate sensitive data.
- **Lateral movement** — compromised Docker hosts provide a pivot point into internal networks. Attackers can deploy containers with network access to internal services, scan internal infrastructure, and compromise adjacent systems.
- **Container registry poisoning** — attackers can push malicious images to private registries accessible from the compromised host, enabling supply chain attacks.
- **Denial of service** — attackers can stop or delete all running containers, destroy volumes, and disrupt production services.
- **Ransomware deployment** — privileged container access allows attackers to deploy ransomware that encrypts both container filesystems and the host system.

An exposed Docker API on port 2375 is equivalent to publishing root SSH credentials to the internet. It is consistently ranked as one of the most critical cloud security misconfigurations. NEVER expose Docker's API without TLS authentication (port 2376 with client certificates), and even then, NEVER expose it to the public internet.

---

#### Port 8333 — Bitcoin (Bitcoin P2P Network, mainnet)

**Banner**: Bitcoin protocol version message (98 bytes)

**Purpose**: Sends a complete Bitcoin protocol version message that Bitcoin Core nodes exchange during peer discovery. The message includes:
- Magic bytes: `0xF9BEB4D9` (Bitcoin mainnet identifier)
- Command: "version" (12-byte null-padded ASCII)
- Protocol version: 70016 (Bitcoin Core 25.0 protocol)
- Services: 1 (NODE_NETWORK — full node with complete blockchain)
- Timestamp: current Unix epoch
- User agent: `/Satoshi:25.0.0/` (identifies as Bitcoin Core 25.0)
- Start height: ~850000 (realistic mainnet block height)
- Relay: true (willing to relay transactions)

**Why it's convincing**: This is a complete, valid Bitcoin P2P protocol version message that exactly matches what Bitcoin Core nodes send during initial handshake. Bitcoin network crawlers, SPV clients, and blockchain explorers will recognize this as a real Bitcoin full node.

**Why this port is targeted**: Port 8333 is heavily scanned by:
- **Blockchain network mapping** — researchers and attackers map the Bitcoin P2P network topology to understand node distribution
- **Unpatched node exploitation** — older Bitcoin Core versions have known vulnerabilities (CVE-2018-17144 inflation bug, DoS vulnerabilities)
- **Wallet reconnaissance** — identifying hosts running Bitcoin Core may indicate the presence of cryptocurrency wallets with significant holdings
- **Eclipse attacks** — attackers attempt to control a node's peer connections to isolate it from the network and manipulate its view of the blockchain
- **Cryptocurrency intelligence** — nation-state actors and financial institutions monitor Bitcoin node distribution for geopolitical and economic analysis

Port 8333 is one of the most critical cryptocurrency infrastructure ports and is constantly probed by both legitimate network researchers and attackers seeking to exploit or manipulate Bitcoin nodes.

---

#### Port 8443 — HTTPS-Alt (HTTP over TLS, alternate port)

**Banner**: Same TLS alert as port 443 (`\x15\x03\x01\x00\x02\x02\x28`)

**Purpose**: Port 8443 is a common alternate HTTPS port (used by Tomcat, application servers, control panels). Sends the same TLS handshake_failure alert as port 443.

**Why it's convincing**: See port 443 description. This port catches scanners looking for HTTPS on non-standard ports.

---

#### Port 8545 — Ethereum-RPC (Ethereum JSON-RPC HTTP Endpoint)

**Banner**: HTTP 200 with JSON-RPC error response:

```
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
Content-Length: 58\r\n
\r\n
{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}
```

**Purpose**: Mimics the exact response that geth (Go Ethereum), Nethermind, and other Ethereum clients return when receiving a malformed JSON-RPC request on their HTTP endpoint.

**Why it's convincing**: This is byte-for-byte identical to what a real Ethereum node returns for an invalid JSON-RPC request. The error code `-32600` (Invalid Request) is from the JSON-RPC 2.0 specification and is the standard response when the JSON payload is invalid or missing required fields. Ethereum reconnaissance tools and web3 libraries will recognize this as a real geth or compatible Ethereum node.

**Why this port is targeted**: Port 8545 is one of the most critical and heavily-scanned cryptocurrency ports:
- **Wallet draining** — an exposed Ethereum RPC endpoint allows attackers to call `eth_sendTransaction`, `personal_unlockAccount`, and other methods to drain wallets with unlocked accounts or weak authentication
- **Private key extraction** — attackers can enumerate accounts with `eth_accounts` and potentially extract private keys if the node is misconfigured
- **Smart contract exploitation** — exposed RPC allows deployment of malicious contracts, interaction with vulnerable contracts, and front-running of transactions
- **Blockchain state access** — attackers read private transaction history, account balances, and contract storage to identify high-value targets
- **DeFi protocol manipulation** — access to a node's mempool and transaction submission allows MEV (Maximal Extractable Value) attacks, sandwich attacks, and flash loan exploits
- **Cryptojacking** — attackers use exposed nodes as free infrastructure for blockchain queries and transaction relay

Port 8545 is the default geth HTTP RPC port and is one of the highest-value targets in cryptocurrency infrastructure. Misconfigured nodes with `--http` enabled and `--http.addr 0.0.0.0` or `--http.corsdomain *` are catastrophic security failures.

---

#### Port 8546 — Ethereum-WS (Ethereum WebSocket JSON-RPC Endpoint)

**Banner**: HTTP 426 Upgrade Required response:

```
HTTP/1.1 426 Upgrade Required\r\n
Connection: Upgrade\r\n
Upgrade: websocket\r\n
\r\n
```

**Purpose**: Sends the standard HTTP 426 status code that geth and other Ethereum clients return when a non-WebSocket client attempts to connect to the WebSocket RPC endpoint.

**Why it's convincing**: This is the exact response that geth returns when a plain HTTP request is sent to port 8546 (the default WebSocket RPC port with `--ws` enabled). The HTTP 426 status specifically indicates that the server requires protocol upgrade to WebSocket, which is standard behavior for WebSocket servers without HTTP fallback. Scanners will recognize this as a real Ethereum WebSocket RPC endpoint.

**Why this port is targeted**: Port 8546 has the same catastrophic risks as 8545:
- **Real-time wallet draining** — WebSocket provides persistent connections for subscribing to events and sending rapid transaction sequences
- **Subscription-based attacks** — attackers subscribe to `newPendingTransactions` to front-run high-value trades in DeFi protocols
- **MEV extraction** — WebSocket's low latency makes it ideal for mempool monitoring and transaction ordering manipulation
- **Event log exploitation** — subscription to contract events leaks sensitive business logic and user activity patterns

Port 8546 is often scanned alongside 8545 as part of comprehensive Ethereum node reconnaissance. Many node operators who expose 8545 also expose 8546, making it a high-probability secondary attack vector.

---

#### Port 9100 — Printer (HP JetDirect / Printer Services)

**Banner**: PJL (Printer Job Language) INFO STATUS response

**Purpose**: Sends a complete PJL status response:
```
@PJL INFO STATUS
CODE=10001
DISPLAY="Ready"
ONLINE=TRUE
```

This is the exact response format that HP JetDirect network printers and printer servers return when queried via raw TCP port 9100.

**Why it's convincing**: Port 9100 is the HP JetDirect / AppSocket / RAW printing protocol port. The PJL INFO STATUS command is a standard printer query, and this response matches what real HP printers and compatible devices return. Printer reconnaissance tools will recognize this as a real network printer.

**Why this port is targeted**: Port 9100 is heavily scanned by:
- **IoT device discovery** — Shodan and Censys actively scan for exposed printers to index
- **Printer exploitation** — printers are soft targets with known vulnerabilities (HP LaserJet arbitrary code execution, SNMP exploits, buffer overflows)
- **Information disclosure** — printers often leak sensitive information through status pages, stored print jobs, and address book data
- **Network pivot points** — compromised printers can be used for network reconnaissance and lateral movement (PrintNightmare, etc.)
- **PJL command injection** — attackers abuse PJL commands to extract data, modify settings, or execute arbitrary PostScript/PCL

Port 9100 is one of the most-scanned IoT ports and represents a large attack surface for device compromise.

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

#### Port 9735 — Lightning (Lightning Network P2P, BOLT #8)

**Banner**: 50-byte Act One response (Noise_XK handshake)

**Purpose**: Sends a complete BOLT #8 (Lightning Network encryption and authentication) Act One response. The response consists of:
- Version byte: `0x00` (BOLT #8 version 0)
- Ephemeral public key: 33 bytes (secp256k1 compressed public key)
- Poly1305 authentication tag: 16 bytes

This is the first message in the Noise_XK handshake that Lightning Network nodes (lnd, c-lightning, eclair) use for encrypted P2P communication.

**Why it's convincing**: The BOLT #8 handshake is the mandatory authentication and encryption layer for all Lightning Network communication. This 50-byte Act One response exactly matches what real Lightning nodes send during connection establishment. Lightning Network scanners and node discovery tools will recognize this as a real Lightning peer.

**Why this port is targeted**: Port 9735 is the standard Lightning Network P2P port and is targeted by:
- **Payment channel topology mapping** — attackers and researchers map the Lightning Network graph to identify high-liquidity nodes and routing hubs
- **Channel liquidity analysis** — identifying nodes with significant channel balances for targeted attacks or routing manipulation
- **Routing policy exploitation** — understanding network topology allows attackers to identify and exploit routing vulnerabilities (balance discovery, jamming attacks)
- **Node fingerprinting** — different Lightning implementations (lnd, c-lightning, eclair) have subtle handshake timing differences that can be fingerprinted
- **Eclipse attacks** — isolating a Lightning node from the network by controlling its peer connections to manipulate routing or steal funds
- **DoS attacks** — flooding nodes with handshake requests to exhaust resources

Port 9735 represents direct access to the Lightning Network's Layer 2 payment infrastructure and is a high-value reconnaissance target for attackers seeking to exploit Bitcoin payment channels.

---

#### Port 10009 — Lightning-gRPC (Lightning Network lnd gRPC API)

**Banner**: HTTP/2 SETTINGS frame (9 bytes)

**Purpose**: Sends the HTTP/2 server connection preface — specifically the SETTINGS frame that gRPC servers (including lnd) send immediately after accepting a connection:

```
0x00 0x00 0x00 0x04 0x00 0x00 0x00 0x00 0x00
```

This is a zero-length SETTINGS frame (frame type 0x04) with no flags and stream ID 0, which is the standard HTTP/2 server greeting.

**Why it's convincing**: lnd (Lightning Network Daemon) uses gRPC over HTTP/2 for its management API on port 10009 by default. The HTTP/2 SETTINGS frame is the first bytes a gRPC server sends after accepting a connection, before any authentication or RPC calls. Scanners and gRPC clients will recognize this as a real lnd gRPC endpoint.

**Why this port is targeted**: Port 10009 is one of the most critical Lightning Network security targets:
- **Unauthorized fund access** — the lnd gRPC API exposes methods for opening/closing channels, sending payments, and managing on-chain funds. If macaroon authentication is misconfigured or disabled, attackers gain complete control over the node's Bitcoin funds.
- **Macaroon theft** — if the admin macaroon file is accessible via path traversal or misconfigured web servers, attackers can authenticate to the API
- **Channel manipulation** — attackers can force-close channels, drain channel balances, or manipulate routing policies
- **Invoice generation** — attackers can generate invoices to social-engineer payments or manipulate accounting
- **Wallet extraction** — the API allows export of the wallet seed and private keys

An exposed lnd gRPC endpoint without proper authentication is a catastrophic failure equivalent to publishing wallet private keys. Port 10009 is heavily targeted by Lightning Network exploit scanners.

---

#### Port 11211 — Memcached

**Banner**: `ERROR\r\n`

**Purpose**: Memcached text protocol error response.

**Why it's convincing**: Scanners typically send `stats\r\n` or `version\r\n` commands to fingerprint memcached. Responding with `ERROR` is a valid memcached response indicating the command was not understood or not allowed. This is enough to fingerprint as memcached without implementing the full protocol.

---

#### Port 18080 — Monero-P2P (Monero P2P Network, monerod)

**Banner**: Levin protocol handshake response (101 bytes)

**Purpose**: Sends a complete Levin protocol header and handshake response that Monero daemon nodes (monerod) exchange during peer discovery. The response includes:
- Levin protocol signature: `0x0121010101010101` (8-byte magic value identifying Levin protocol)
- Payload length: indicates size of serialized handshake data
- Command: 1001 (COMMAND_HANDSHAKE response)
- Return code: 1 (success)
- Flags: LEVIN_PACKET_RESPONSE (0x01)

**Why it's convincing**: Monero uses the Levin protocol (a binary RPC protocol) for all P2P communication between monerod nodes. This handshake response exactly matches what real Monero nodes send during peer connection establishment. Monero network crawlers and other monerod instances will recognize this as a real Monero P2P node.

**Why this port is targeted**: Port 18080 is the standard Monero P2P port and is heavily scanned by:
- **Privacy coin network mapping** — researchers and law enforcement map the Monero P2P network to analyze transaction propagation and deanonymize users
- **Node reconnaissance** — identifying hosts running Monero mining or transaction relay operations
- **Exploit scanning** — older monerod versions have known vulnerabilities (transaction verification bypasses, DoS vulnerabilities)
- **Mining operation detection** — Monero is the most-mined privacy coin, and P2P nodes often indicate mining infrastructure
- **Cryptojacking detection** — security teams scan for unauthorized Monero mining operations on compromised systems
- **Sybil attacks** — attackers attempt to control large portions of the Monero P2P network to manipulate transaction routing or deanonymize users

Monero's focus on privacy makes its network infrastructure a high-value intelligence target for both attackers and law enforcement.

---

#### Port 18081 — Monero-RPC (Monero JSON-RPC Endpoint, monerod)

**Banner**: HTTP 200 with JSON-RPC error response:

```
HTTP/1.1 200 OK\r\n
Content-Type: application/json\r\n
Content-Length: 68\r\n
\r\n
{"id":"0","jsonrpc":"2.0","error":{"code":-1,"message":"Invalid request"}}
```

**Purpose**: Mimics the exact response that monerod (Monero daemon) returns when receiving a malformed or unauthorized JSON-RPC request on the restricted RPC endpoint.

**Why it's convincing**: This is the standard Monero RPC error response format. The error code `-1` with message "Invalid request" is what monerod returns for requests that fail validation. Monero RPC clients and scanners will recognize this as a real monerod RPC endpoint, typically running in restricted mode (the default configuration that blocks sensitive methods).

**Why this port is targeted**: Port 18081 is the Monero RPC port and is targeted by:
- **Wallet balance enumeration** — even restricted RPC endpoints expose methods like `get_balance`, `get_address`, and `get_transfers` that leak wallet information
- **Transaction history access** — attackers query transaction history to identify high-value wallets or track payment flows
- **Privacy deanonymization** — combining RPC data with network analysis can potentially deanonymize Monero transactions
- **Unauthorized transfer attempts** — if the RPC is unrestricted or misconfigured (missing `--restricted-rpc`), attackers can call `transfer` and `sweep_all` to steal funds
- **Mining operation intelligence** — RPC endpoints reveal whether the node is mining, block discovery rates, and hash power
- **Daemon reconnaissance** — version strings and configuration data exposed via RPC help attackers identify vulnerable monerod versions

An unrestricted Monero RPC endpoint (exposed without `--restricted-rpc`) is a critical vulnerability allowing complete wallet access and fund theft.

---

#### Port 18789 — OpenClaw (OpenClaw AI Assistant Gateway)

**Banner**: HTTP 426 Upgrade Required response:

```
HTTP/1.1 426 Upgrade Required\r\n
Connection: Upgrade\r\n
Upgrade: websocket\r\n
Content-Type: text/plain\r\n
Content-Length: 25\r\n
\r\n
WebSocket upgrade required
```

**Purpose**: Mimics the OpenClaw Gateway control plane HTTP/WebSocket endpoint response when a non-WebSocket HTTP request is received.

**Why it's convincing**: This is the exact response a real OpenClaw Gateway returns when it receives a plain HTTP request instead of a WebSocket upgrade request. The HTTP 426 status code specifically indicates that the server requires the client to switch to a different protocol (WebSocket in this case), which is the standard behavior for WebSocket servers that don't support fallback HTTP endpoints. The response headers correctly specify the required upgrade protocol, making it indistinguishable from a real OpenClaw installation.

**Why this port is targeted**: OpenClaw (https://github.com/openclaw/openclaw) is a popular open-source AI assistant platform with 327,000+ GitHub stars. Its Gateway component listens on TCP port 18789 by default (`ws://127.0.0.1:18789`) as the central control plane for managing AI assistant sessions, multi-channel integrations (WhatsApp, Telegram, Slack, Discord, SMS, Email), tool access (browser automation, shell execution, file operations, API calls), and event streaming. Attackers actively scan for exposed OpenClaw Gateways to:
- Access and exfiltrate conversation histories and session data
- Abuse tool access to execute arbitrary commands on the host system
- Hijack AI assistant sessions to manipulate conversations or inject malicious responses
- Exploit misconfigured channel integrations to gain access to connected messaging platforms
- Extract API keys, credentials, and configuration data stored in the Gateway

The default port 18789 is well-documented in OpenClaw's installation guides and is a known reconnaissance target for attackers seeking to compromise AI assistant infrastructure.

---

#### Port 27017 — MongoDB (MongoDB Database)

**Banner**: MongoDB OP_REPLY wire protocol message with BSON error document

**Purpose**: Sends a BSON document `{ok: 0.0, errmsg: "Authentication required", code: 13}` indicating authentication is required.

**Why it's convincing**: MongoDB uses a binary wire protocol. This is a valid OP_REPLY message with an error document — exactly what MongoDB sends when authentication is enabled and the client has not authenticated. Scanners looking for open MongoDB instances will see this as a real MongoDB server with auth enabled.

**Why this port is targeted**: Port 27017 is one of the most heavily-scanned database ports:
- **Data exfiltration** — MongoDB databases often contain sensitive application data, user credentials, and business records
- **Ransomware attacks** — MongoDB Apocalypse and similar ransomware campaigns have encrypted thousands of unsecured MongoDB instances
- **Authentication bypass** — attackers look for MongoDB instances with authentication disabled (the old default before MongoDB 2.6)
- **NoSQL injection** — exposed MongoDB instances may be vulnerable to query injection attacks
- **Database reconnaissance** — attackers enumerate collections and documents to identify high-value data stores

Exposed MongoDB instances have been responsible for some of the largest data breaches in history due to misconfigured authentication and network exposure.

---

#### Port 30303 — Ethereum-P2P (Ethereum P2P Network, devp2p/RLPx)

**Banner**: No banner (connection accept only)

**Purpose**: Accepts TCP connections silently without sending data, exactly as real Ethereum nodes do when waiting for the initiator's RLPx encrypted authentication message.

**Why it's convincing**: Ethereum's devp2p protocol (which includes RLPx encrypted transport) uses a handshake where the initiator sends first. Real Ethereum nodes (geth, Nethermind, Besu, Erigon) accept the connection and wait for the client to send the encrypted `auth` message before responding with an `ack`. By accepting connections without sending a banner, webTraffik fingerprints identically to a real Ethereum node.

**Why this port is targeted**: Port 30303 is scanned for both TCP (RLPx) and UDP (discovery):
- **Ethereum network mapping** — researchers map the global Ethereum P2P topology to understand node distribution and network health
- **Eclipse attacks** — attackers attempt to control a node's peer connections to isolate it and manipulate its view of the blockchain
- **Node fingerprinting** — different Ethereum clients (geth, Nethermind, Besu) have subtle protocol differences that can be fingerprinted
- **Consensus attack research** — analyzing P2P behavior to identify potential consensus-layer vulnerabilities
- **Network partition detection** — monitoring node connectivity to detect or induce network splits
- **MEV infrastructure reconnaissance** — identifying well-connected nodes used for MEV extraction and transaction ordering

Port 30303 is the foundation of Ethereum's P2P layer and is constantly scanned by network researchers, attackers, and monitoring infrastructure.

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
| 1434 | MSSQL-Mon | MSSQL Browser/Monitor Service |
| 1900 | SSDP/UPnP | Simple Service Discovery Protocol / Universal Plug and Play |
| 5060 | SIP | Session Initiation Protocol (VoIP) |
| 30303 | Ethereum-Disc | Ethereum Node Discovery Protocol (devp2p discv4/discv5) |

**Why these ports**:
- **DNS (53)**: Used by DNS amplification attacks and reconnaissance
- **NTP (123)**: Target of NTP amplification DDoS attacks
- **SNMP (161)**: Common target for device enumeration and exploitation
- **MSSQL-Mon (1434)**: Database reconnaissance and SQL Slammer-style attacks. The MSSQL Browser/Monitor Service on UDP 1434 is queried to discover SQL Server instances on the network. Scanners hit this port alongside TCP 1433 to enumerate database servers. By capturing without responding, webTraffik logs reconnaissance attempts without participating in amplification attacks or revealing database information.
- **SSDP (1900)**: Used by UPnP exploits and device discovery scans
- **SIP (5060)**: VoIP service discovery and SIP scanning
- **Ethereum-Disc (30303)**: Ethereum's UDP-based node discovery protocol (discv4 and the newer discv5). Ethereum nodes broadcast UDP discovery ping packets to find peers and maintain the distributed hash table (DHT) of node information. Bots and network mappers send discovery packets to enumerate the Ethereum P2P network. This port complements TCP 30303 (RLPx encrypted transport) for complete Ethereum network reconnaissance capture.

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

**Last synchronized with**: `services.go` as of the current codebase state (42 TCP services, 7 UDP services, 1 Minecraft service, 17 HTTP ports)
