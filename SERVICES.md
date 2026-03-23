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
| 102 | S7comm | Siemens S7 PLC (ISO-TSAP) | 22-byte COTP Connection Confirm (CC) TPDU with rack 0 slot 2 |
| 110 | POP3 | Post Office Protocol 3 | `+OK POP3 server ready` — standard POP3 greeting |
| 135 | RPC | Microsoft DCE/RPC Endpoint Mapper | DCE/RPC bind_nak rejection (LOCAL_LIMIT_EXCEEDED) |
| 139 | NetBIOS | NetBIOS Session Service | Negative session response (not listening on called name) |
| 143 | IMAP | Internet Message Access Protocol | `* OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.` — mimics Dovecot IMAP |
| 443 | HTTPS | HTTP over TLS | TLS 1.0 Alert (fatal, handshake_failure) — realistic response to ClientHello |
| 445 | SMB | Server Message Block | Minimal SMB2 NEGOTIATE response with STATUS_NOT_SUPPORTED — fingerprints as Windows SMB |
| 502 | Modbus | Modbus/TCP | 9-byte Modbus Exception Response (function 0x83, exception code 0x01) |
| 554 | RTSP | Real Time Streaming Protocol | `RTSP/1.0 401 Unauthorized` with Digest authentication challenge — mimics Hikvision IP camera |
| 631 | IPP | Internet Printing Protocol / CUPS | HTTP 200 with `Server: CUPS/2.4 IPP/2.1` header and HTML redirect |
| 993 | IMAPS | IMAP over SSL/TLS | TLS handshake_failure alert (same as port 443) |
| 995 | POP3S | POP3 over SSL/TLS | TLS handshake_failure alert (same as port 443) |
| 1433 | MSSQL | Microsoft SQL Server | TDS pre-login response indicating version 15.00.2000, encryption not supported |
| 1521 | Oracle | Oracle Database TNS Listener | TNS Refuse packet with error code 1153 |
| 1723 | PPTP | Point-to-Point Tunneling Protocol VPN | PPTP Start-Control-Connection-Reply (156 bytes) |
| 2082 | cPanel-HTTP | cPanel Unencrypted HTTP | HTTP 200 with `Server: cpsrvd/11.112` and `X-CPanel-Version: 11.112` |
| 2083 | cPanel-HTTPS | cPanel Encrypted HTTPS | TLS handshake_failure alert (same as port 443) |
| 2375 | Docker | Docker Daemon REST API (unencrypted) | HTTP 200 OK mimicking Docker's `/_ping` endpoint with Api-Version and Docker headers |
| 3283 | ARD | Apple Remote Desktop | 2 bytes: `0x00 0x02` (server capability word) |
| 3306 | MySQL | MySQL Database | MySQL 8.0.35 handshake packet (Protocol 10) with caching_sha2_password |
| 3333 | Stratum | Cryptocurrency Mining Pool Protocol | JSON-RPC mining.notify notification — mimics mining pool distributing work |
| 3389 | RDP | Remote Desktop Protocol | X.224 Connection Confirm PDU with RDP_NEG_RSP (PROTOCOL_RDP, no enhanced security) |
| 4444 | Metasploit | Metasploit Default Reverse Shell | No banner (silent accept) |
| 4899 | Radmin | Remote Administrator | `RFB 003.006\n` — Radmin v3 RFB-like handshake |
| 5432 | PostgreSQL | PostgreSQL Database | ErrorResponse: `FATAL: no pg_hba.conf entry for host` — realistic rejection |
| 5555 | ADB | Android Debug Bridge | ADB CNXN connect response with device identity string |
| 5900 | VNC | Virtual Network Computing | `RFB 003.008\n` — RFB protocol version handshake for VNC 3.8 |
| 5985 | WinRM-HTTP | Windows Remote Management HTTP | HTTP 404 with `Server: Microsoft-HTTPAPI/2.0` |
| 5986 | WinRM-HTTPS | Windows Remote Management HTTPS | TLS handshake_failure alert (same as port 443) |
| 6000 | X11 | X Window System | X11 connection-refused response with "No protocol specified" error |
| 6379 | Redis | Redis In-Memory Database | `-DENIED Redis is running in protected mode` — mimics Redis protected mode |
| 6667 | IRC | Internet Relay Chat | IRC NOTICE AUTH hostname lookup messages |
| 8291 | Winbox | MikroTik Winbox | 4 bytes: `0x01 0x00 0x00 0x00` (null-session banner) |
| 8333 | Bitcoin | Bitcoin P2P Network (mainnet) | Bitcoin protocol version message (magic 0xF9BEB4D9, version 70016, /Satoshi:25.0.0/) |
| 8443 | HTTPS-Alt | HTTP over TLS (alternate port) | Same TLS handshake_failure alert as port 443 |
| 8545 | Ethereum-RPC | Ethereum JSON-RPC HTTP Endpoint | HTTP 200 with JSON-RPC error {"code":-32600,"message":"Invalid Request"} |
| 8546 | Ethereum-WS | Ethereum WebSocket JSON-RPC Endpoint | HTTP 426 Upgrade Required — geth WebSocket endpoint response |
| 8728 | RouterOS-API | MikroTik RouterOS API | RouterOS API sentence: `!done` + `=ret=ROS_7.14` (length-prefixed) |
| 8729 | RouterOS-API-SSL | MikroTik RouterOS API-SSL | TLS handshake_failure alert (same as port 443) |
| 8899 | Hikvision-HTTP | Hikvision IP Camera HTTP Web UI | HTTP 200 OK with `Server: App-webs/` header and redirect to `/doc/page/login.asp` |
| 9100 | Printer | HP JetDirect / Printer Services | PJL INFO STATUS "Ready" response |
| 9200 | Elasticsearch | Elasticsearch Search Engine | HTTP 200 with JSON body mimicking Elasticsearch 7.17.16 node info |
| 9735 | Lightning | Lightning Network P2P (BOLT #8) | 50-byte Act One response (Noise_XK handshake) |
| 10009 | Lightning-gRPC | Lightning Network lnd gRPC API | HTTP/2 SETTINGS frame (server connection preface) |
| 11211 | Memcached | Memcached In-Memory Cache | `ERROR\r\n` — memcached text protocol error response |
| 18080 | Monero-P2P | Monero P2P Network (monerod) | Levin protocol header with signature 0x0121010101010101 and handshake command |
| 18081 | Monero-RPC | Monero JSON-RPC Endpoint (monerod) | HTTP 200 with JSON-RPC error — standard Monero RPC error response |
| 18789 | OpenClaw | OpenClaw AI Assistant Gateway | HTTP 426 Upgrade Required with WebSocket upgrade headers |
| 20000 | DNP3 | Distributed Network Protocol (SCADA) | 16-byte DNP3 Unsolicited Response frame (device restart flag) |
| 27017 | MongoDB | MongoDB Database | OP_REPLY with BSON `{ok:0, errmsg:"Authentication required", code:13}` |
| 30303 | Ethereum-P2P | Ethereum P2P Network (devp2p/RLPx) | No banner (connection accept only) — waits for initiator's encrypted auth message |
| 34567 | XMEye | XMEye / Generic DVR Clone Protocol | 20-byte header + JSON payload with DVR login challenge response |
| 37777 | Dahua | Dahua DVR/NVR Proprietary Protocol | 20-byte Dahua challenge packet with magic bytes `0xFF 0x01` |
| 44818 | EtherNet/IP | CIP / Rockwell PLC | 65-byte List Identity reply (1756-ENBT/A, vendor ID 1, device type 2) |

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

#### Port 102 — S7comm (Siemens S7 PLC / ISO-TSAP)

**Banner**: 22-byte COTP Connection Confirm (CC) TPDU

**Purpose**: Sends a complete ISO-TSAP / COTP Connection Confirm packet that Siemens S7-300/400/1200/1500 PLCs send when accepting a connection. The response includes:
- TPKT header: version 0x03, reserved 0x00, length 22
- COTP header: length 17, PDU type 0xD0 (Connection Confirm)
- Destination reference: 0x0001
- Source reference: 0x0000
- Class/Option: 0x00 (Class 0)
- Parameter code 0xC1 (TPDU Size): value 0x0A (1024 bytes)
- Parameter code 0xC2 (Calling TSAP): `\x01\x00` (rack 0, slot 0 / initiator)
- Parameter code 0xC3 (Called TSAP): `\x01\x02` (rack 0, slot 2 / S7-300 default)

**Why it's convincing**: This is byte-for-byte identical to what a real Siemens S7-300 PLC sends during the ISO-TSAP handshake (the transport layer beneath the S7comm protocol). The TPDU-size=1024 and called TSAP pointing at rack 0 slot 2 are the exact defaults for S7-300 PLCs. Shodan's "siemens" filter and industrial reconnaissance tools like PLCScan fingerprint this exact packet. The response structure matches the ISO 8073 COTP specification perfectly.

**Why this port is targeted**: Port 102 represents one of the most CRITICAL industrial control system (ICS/SCADA) attack surfaces on the internet:
- **Stuxnet legacy** — Port 102 gained global notoriety as the primary attack vector for Stuxnet, the nation-state malware that sabotaged Iranian nuclear centrifuges. The S7comm protocol has zero authentication in its default configuration, allowing any client to read/write PLC memory, start/stop the CPU, and upload/download programs. Stuxnet exploited this to modify centrifuge speeds and cause physical damage while hiding the modifications from monitoring systems.
- **Zero authentication** — Siemens S7 PLCs do NOT require authentication for S7comm connections by default. The ISO-TSAP handshake (which this banner emulates) is purely a connection establishment mechanism with no credentials, tokens, or encryption. Once the handshake completes, the attacker has full read/write access to PLC data blocks, flags, timers, counters, and program logic.
- **Critical infrastructure targeting** — S7 PLCs are deployed in power plants, water treatment facilities, chemical plants, manufacturing lines, oil refineries, natural gas pipelines, and other critical infrastructure. An exposed port 102 indicates direct access to industrial control logic. Attackers (including nation-state APT groups) actively scan for exposed S7 PLCs to:
  - Map critical infrastructure networks and identify high-value targets
  - Exfiltrate proprietary process control logic and industrial secrets
  - Sabotage physical processes (modify setpoints, disable safety interlocks, alter PID controller parameters)
  - Cause equipment damage, production shutdowns, or safety incidents
- **Shodan indexing** — Shodan actively scans and indexes exposed S7 PLCs worldwide. Thousands of PLCs are discoverable via searches like `port:102 country:US` or `"Siemens, SIMATIC"`. Each indexed PLC is a potential attack target.
- **Safety system compromise** — S7 PLCs often implement safety-critical logic (emergency shutdown systems, pressure relief, temperature interlocks). Unauthorized modification of this logic can cause catastrophic safety failures, explosions, chemical releases, or loss of life.
- **Intellectual property theft** — PLC programs contain proprietary manufacturing processes, recipes, control algorithms, and trade secrets. Attackers exfiltrate these programs to steal competitive intelligence or enable industrial espionage.
- **Ransomware targeting** — Industrial ransomware (LockerGoga, EKANS/SNAKE, Ryuk variants) specifically targets ICS environments. Compromised PLCs can be used to halt production, encrypt SCADA historian databases, or hold critical processes hostage.

Port 102 is THE canonical ICS/SCADA port on the internet and is one of the highest-risk exposures in critical infrastructure. The combination of zero authentication + physical process control + Stuxnet precedent makes this port a primary target for nation-state APT groups, industrial saboteurs, and ransomware operators.

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

#### Port 502 — Modbus/TCP

**Banner**: 9-byte Modbus Exception Response

**Purpose**: Sends a complete Modbus/TCP exception response indicating an illegal function error:
- Transaction ID: `0x0001` (echoes typical scanner request)
- Protocol ID: `0x0000` (Modbus protocol identifier)
- Length: `0x0003` (3 bytes of data follow)
- Unit ID: `0x01` (device address 1)
- Function code: `0x83` (Read Holding Registers + 0x80 exception flag)
- Exception code: `0x01` (Illegal Function)

This is the exact response a Modbus TCP device (PLC, RTU, gateway) sends when rejecting an invalid function code or unauthorized request.

**Why it's convincing**: Modbus/TCP is the most widely deployed industrial protocol on the planet. The exception response format is defined in the Modbus specification and is identical across millions of devices from hundreds of vendors (Schneider Electric, ABB, Siemens, Allen-Bradley, Honeywell, Yokogawa, etc.). The transaction ID echo + protocol ID `0x0000` + exception function code is the universal Modbus fingerprint. Reconnaissance tools like ModbusPal, modscan, and Shodan's Modbus probe recognize this as a real Modbus device.

**Why this port is targeted**: Port 502 is one of the MOST heavily-scanned industrial ports globally:
- **Zero authentication** — Modbus has ZERO security features. No authentication, no encryption, no access control. The protocol was designed in 1979 for serial RS-232 connections within a single control cabinet. Any client that can reach port 502 can read/write any register, coil, or input. This is not a vulnerability — it is the protocol's design.
- **Universal deployment** — Modbus is the de facto standard for industrial device communication. It's deployed in: power generation and distribution (SCADA RTUs), water/wastewater treatment, oil and gas pipelines, building automation (HVAC, lighting, elevators), manufacturing (assembly lines, robots, sensors), transportation (traffic lights, railroad signaling), and renewable energy (solar inverters, wind turbines). Modbus is EVERYWHERE.
- **Direct process control** — Modbus registers directly map to physical inputs/outputs, setpoints, and control logic. Attackers can:
  - Read sensor values (temperatures, pressures, flow rates, levels) to map the physical process
  - Write to output coils to activate valves, motors, pumps, heaters, or circuit breakers
  - Modify setpoints to cause equipment damage (overheat boilers, overpressure tanks, overdose chemicals)
  - Disable safety interlocks and alarms
  - Trigger emergency shutdowns or prevent emergency stops
- **ICS honeypot and reconnaissance** — Shodan indexes hundreds of thousands of exposed Modbus devices worldwide (search: `port:502`). Each exposed device reveals vendor identification, device model, firmware version, and register map structure. Attackers use this intelligence to:
  - Identify vulnerable firmware versions (CVE targeting)
  - Map SCADA network topology
  - Build exploit databases for specific PLC/RTU models
  - Plan targeted attacks against specific industries or facilities
- **Critical infrastructure targeting** — Nation-state APT groups (Sandworm/Industroyer, Triton/Trisis, Havex, BlackEnergy) specifically target Modbus-enabled SCADA systems. Industroyer's attack on Ukraine's power grid in 2016 used Modbus to directly command circuit breakers. Triton malware targeted Schneider Electric Triconex safety PLCs (which use Modbus) to disable emergency shutdown systems at a Saudi petrochemical plant.
- **Supply chain and IoT botnet recruitment** — Modbus-enabled IoT devices (smart meters, solar inverters, EV chargers, building controllers) are recruited into botnets. VPNFilter and Mirai variants specifically target Modbus devices for DDoS swarms and cryptomining.
- **Ransomware enablement** — Industrial ransomware operators use exposed Modbus ports to map OT networks, identify critical assets, and disable safety systems before deploying ransomware on IT networks. The goal is to maximize operational disruption and ransom payment pressure.

Port 502 is the single most dangerous industrial protocol port to expose to the internet. The combination of universal deployment + zero security + direct physical process access makes it the #1 reconnaissance target for industrial cyber-physical attacks.

---

#### Port 554 — RTSP (Real Time Streaming Protocol)

**Banner**: 
```
RTSP/1.0 401 Unauthorized\r\n
CSeq: 1\r\n
WWW-Authenticate: Digest realm="IP Camera(C6473WD)", nonce="4f3a9c1b7e2d8f05", algorithm="MD5"\r\n
Server: Hikvision-Webs\r\n
\r\n
```

**Purpose**: Sends an RTSP 401 Unauthorized response with Digest authentication challenge, impersonating a Hikvision IP camera. This is the exact response that Hikvision cameras send when an unauthenticated client attempts to access an RTSP stream. The response includes:
- Status line: `RTSP/1.0 401 Unauthorized` indicating authentication required
- CSeq header: matches the client's command sequence number
- WWW-Authenticate header: Digest authentication challenge with realm string `IP Camera(C6473WD)` (a real Hikvision camera model identifier)
- Server header: `Hikvision-Webs` — the exact server string Hikvision cameras use (NOT the generic "Hikvision RTSP Server" — it's specifically "Hikvision-Webs", which is their embedded web server name)

**Why it's convincing**: The `Hikvision-Webs` server header combined with the Digest realm string `IP Camera(C6473WD)` is the exact fingerprint that Shodan, Censys, and reconnaissance scanners use to identify Hikvision IP cameras. The 401 Unauthorized response is more realistic than a 200 OK because real Hikvision cameras require authentication before allowing stream access. This banner fingerprints identically to millions of deployed Hikvision cameras and cheap Hikvision-compatible clones.

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

#### Port 631 — IPP (Internet Printing Protocol / CUPS)

**Banner**: HTTP 200 response with CUPS headers and HTML redirect

**Purpose**: Sends an HTTP response mimicking the CUPS web interface:
```
HTTP/1.1 200 OK\r\n
Server: CUPS/2.4 IPP/2.1\r\n
Content-Type: text/html\r\n
Content-Length: 85\r\n
\r\n
<html><head><title>Home - CUPS 2.4</title></head><body><h1>CUPS 2.4</h1></body></html>
```

The response includes:
- Server header: `CUPS/2.4 IPP/2.1` — identifies as CUPS 2.4 with IPP (Internet Printing Protocol) 2.1 support
- HTML page with CUPS branding

**Why it's convincing**: This is exactly what the CUPS web interface (http://localhost:631) returns when accessed via HTTP. The `Server: CUPS/2.4 IPP/2.1` header is the universal fingerprint that Shodan and printer reconnaissance tools use to identify exposed CUPS servers. CUPS is the default printing system on Linux, macOS, and BSD systems, making this banner instantly recognizable to automated scanners.

**Why this port is targeted**: Port 631 represents a CRITICAL and recently-exploited vulnerability surface:
- **CVE-2024-47176 and the CUPS RCE chain** — In September 2024, a critical remote code execution vulnerability chain was disclosed affecting CUPS. The exploit chain (CVE-2024-47176 + CVE-2024-47076 + CVE-2024-47175 + CVE-2024-47177) allows an attacker to execute arbitrary commands on any system running CUPS with port 631 exposed. The attack works by:
  - Sending a crafted IPP request to add a malicious printer
  - The malicious printer driver contains command injection payloads
  - When any user prints to the malicious printer (or when CUPS performs maintenance tasks), the payload executes with CUPS privileges (often root)
- **Millions of exposed instances** — CUPS is installed by default on virtually every Linux desktop and server, macOS workstation, and many embedded devices. Shodan finds hundreds of thousands of exposed CUPS instances. Most administrators are unaware that port 631 is accessible from the network or internet.
- **Unauthenticated access** — By default, CUPS allows unauthenticated printer discovery and IPP operations from the local network. Many misconfigurations expose this to the internet. Even "authenticated" CUPS setups often use weak credentials or default accounts.
- **Credential harvesting** — The CUPS web interface requires authentication for administrative functions. Attackers use exposed CUPS instances for credential brute-forcing and reuse attacks (compromised credentials often work across multiple systems).
- **Information disclosure** — CUPS leaks system information: hostnames, usernames, installed printers, recent print jobs (including filenames and metadata), network topology, and connected devices. This intelligence aids further attacks.
- **Print job interception** — Attackers can add rogue printers that capture print jobs, exfiltrating documents sent to the printer (contracts, financial records, PII, credentials, etc.).
- **Denial of service** — Attackers can disable printers, delete print queues, or flood the system with print jobs to exhaust disk space and CPU.
- **Lateral movement** — Compromised CUPS servers provide a foothold into internal networks. Printers often have network access to internal file servers, workstations, and infrastructure that is otherwise firewalled from external access.

Port 631 has gone from a low-priority informational disclosure port to a CRITICAL RCE vector as of September 2024. Every exposed CUPS instance is a potential full system compromise. The CVE-2024-47176 exploit chain is actively being weaponized by exploit frameworks and botnet operators.

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

#### Port 2082 — cPanel HTTP (cPanel Unencrypted HTTP)

**Banner**: HTTP 200 response with cPanel headers

**Purpose**: Sends an HTTP response mimicking the cPanel control panel login page:
```
HTTP/1.1 200 OK\r\n
Server: cpsrvd/11.112\r\n
X-CPanel-Version: 11.112\r\n
Content-Type: text/html\r\n
Content-Length: 42\r\n
\r\n
<html><body>cPanel Login</body></html>
```

The response includes:
- Server header: `cpsrvd/11.112` — cPanel server daemon version 11.112
- X-CPanel-Version header: identifies the cPanel version explicitly
- HTML page with cPanel branding

**Why it's convincing**: The `Server: cpsrvd/` header is the universal fingerprint for cPanel installations. cPanel is the dominant shared web hosting control panel, installed on millions of web hosting servers worldwide. Shodan and reconnaissance scanners specifically search for the `cpsrvd` server header to identify cPanel instances. Port 2082 is the standard unencrypted HTTP port for cPanel (port 2083 is the HTTPS variant).

**Why this port is targeted**: Port 2082 is heavily scanned for cPanel-specific attacks:
- **Credential stuffing** — cPanel login pages are primary targets for credential stuffing attacks. Compromised web hosting credentials allow attackers to: upload malware, deface websites, steal databases, exfiltrate email, modify DNS records, and pivot to other hosted accounts on the same server.
- **Version-specific exploits** — Older cPanel versions have known vulnerabilities (privilege escalation, XSS, CSRF, authentication bypass). Scanners fingerprint the version via the X-CPanel-Version header and launch targeted exploits.
- **Email account compromise** — cPanel provides access to email accounts for all hosted domains. Compromised accounts are used for phishing, spam relay, and business email compromise (BEC) attacks.
- **Domain hijacking** — Attackers with cPanel access can modify DNS records to redirect domains to phishing sites, intercept email, or steal SSL/TLS certificates via Let's Encrypt.
- **Database theft** — cPanel's phpMyAdmin and database management interfaces provide direct access to MySQL databases containing customer data, user credentials, and application secrets.
- **File manager exploitation** — cPanel's file manager allows upload of PHP shells, webshells, and backdoors that provide persistent server access.
- **SEO spam injection** — Compromised cPanel accounts are used to inject hidden spam links, doorway pages, and malicious redirects for black-hat SEO campaigns.

Port 2082 represents the primary attack surface for the shared web hosting industry. Millions of small businesses, bloggers, and organizations rely on cPanel-managed hosting, making this port a high-value target for mass credential attacks.

---

#### Port 2083 — cPanel HTTPS (cPanel Encrypted HTTPS)

**Banner**: TLS handshake_failure alert (same as port 443)

**Purpose**: Sends a TLS 1.0 Alert packet indicating handshake failure:
```
\x15\x03\x01\x00\x02\x02\x28
```

This is the exact binary response that SSL/TLS servers send when rejecting a ClientHello due to configuration mismatch or lack of shared cipher suites.

**Why it's convincing**: Port 2083 is the standard HTTPS port for cPanel. The TLS handshake_failure alert is a realistic response for a TLS server that is present but cannot complete the handshake (due to missing certificates, cipher suite mismatch, or protocol version incompatibility). Scanners looking for HTTPS services on alternate ports will recognize this as an active TLS endpoint. The alert fingerprints identically to real cPanel HTTPS servers that are rejecting connections.

**Why this port is targeted**: Port 2083 is scanned alongside port 2082 as part of cPanel reconnaissance. Attackers prefer HTTPS endpoints (port 2083) for credential theft because the encrypted channel prevents network-based credential interception. The same attacks that target port 2082 also target port 2083: credential stuffing, version-specific exploits, and control panel compromise.

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

#### Port 8899 — Hikvision IP Camera HTTP Web UI

**Banner**: HTTP 200 OK response with Hikvision-specific headers and HTML redirect:

```
HTTP/1.1 200 OK\r\n
Server: App-webs/\r\n
Content-Type: text/html\r\n
Content-Length: 120\r\n
\r\n
<html>
<head>
<meta http-equiv="refresh" content="0; url=/doc/page/login.asp">
</head>
<body>Redirecting...</body>
</html>
```

**Purpose**: Mimics the HTTP web interface of a Hikvision IP camera. The response includes:
- Server header: `App-webs/` — the exact server string used by Hikvision cameras (note the trailing slash — this is not a typo, it's how Hikvision formats this header)
- HTML redirect to `/doc/page/login.asp` — the standard Hikvision camera web UI login page path

**Why it's convincing**: The `Server: App-webs/` header (with the trailing slash) is the fingerprint Shodan and other reconnaissance tools use to identify Hikvision IP cameras. The redirect to `/doc/page/login.asp` is the exact path structure used by real Hikvision camera web interfaces. This port-and-header combination is instantly recognizable as a Hikvision camera to automated scanners.

**Why this port is targeted**: Port 8899 is one of the most heavily-scanned IP camera ports on the internet:
- **Default credential exploitation** — Hikvision cameras are notorious for shipping with default credentials (`admin` with blank password, or `admin`/`12345`). Port 8899 is the HTTP web UI where these credentials are tested. Millions of deployed cameras still use default credentials, making this one of the highest-success-rate ports for botnet recruitment.
- **Hikvision-specific vulnerabilities** — numerous CVEs target Hikvision cameras specifically: CVE-2017-7921 (authentication bypass), CVE-2021-36260 (command injection), CVE-2022-30563 (unrestricted file upload), and many others. Exploit scanners specifically look for the `App-webs/` server header to identify vulnerable targets.
- **Botnet recruitment** — the Mirai botnet and countless variants (Moobot, Gafgyt, Miori) specifically target port 8899 with Hikvision default credentials for recruitment into DDoS swarms.
- **Surveillance access** — attackers gain access to live video feeds, recorded footage, camera settings, and network configuration. Compromised cameras are indexed on sites like Insecam and sold on the dark web.
- **Lateral movement** — cameras often have network access to internal systems (NVRs, management networks) and can be used as pivot points for deeper network penetration.
- **Firmware replacement** — attackers upload malicious firmware to maintain persistent access even after credential changes or reboots.
- **Configuration extraction** — camera configuration files contain WiFi credentials, network topology information, and other sensitive data that aids further attacks.

Hikvision cameras (and the thousands of white-label brands using Hikvision firmware) represent one of the largest and most vulnerable IoT device categories on the internet. Port 8899 is the primary attack surface for these devices.

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

#### Port 20000 — DNP3 (Distributed Network Protocol / SCADA)

**Banner**: 16-byte DNP3 Unsolicited Response frame

**Purpose**: Sends a complete DNP3 Unsolicited Response frame that DNP3 outstations (RTUs, substations, power relays) send to indicate an event or status change:
- Start bytes: `0x05 0x64` (DNP3 magic header)
- Length: `0x14` (20 bytes total frame length)
- Control byte: `0x44` (Unsolicited Response from outstation)
- Destination address: `0xFF 0xFF` (broadcast address)
- Source address: `0x00 0x01` (outstation address 1)
- CRC-16: calculated per DNP3 specification
- Application layer:
  - Control byte: `0xC0` (Final fragment, First fragment)
  - Function code: `0x82` (Unsolicited Response)
  - IIN (Internal Indication) bytes: `0x80 0x00` (device restart flag set)

**Why it's convincing**: DNP3 is the dominant protocol in the electric power industry (SCADA systems, substations, distribution automation) and is also deployed in water/wastewater, oil/gas pipelines, and transportation. The start bytes `0x05 0x64` are the universal DNP3 magic header that reconnaissance tools look for. The Unsolicited Response function code (0x82) with the device restart flag in IIN1 is a realistic and convincing response — it indicates the outstation has just restarted and is announcing its presence to the master station. This is exactly what real DNP3 devices do after power-on or reboot.

**Why this port is targeted**: Port 20000 is the standard DNP3 port and represents CRITICAL infrastructure attack surface:
- **Electric grid SCADA** — DNP3 is the protocol of choice for electric utility SCADA systems. Port 20000 connections provide direct access to substation relays, circuit breakers, voltage regulators, and power distribution automation. Compromised DNP3 devices can:
  - Open or close circuit breakers to cause blackouts
  - Modify relay settings to disable protective functions
  - Alter voltage/frequency setpoints to damage equipment
  - Read real-time grid status and operational data
- **Industroyer/Crashoverride** — The Industroyer malware (used in the 2016 Ukraine power grid attack) specifically targeted IEC 60870-5-104 and DNP3 protocols to send unauthorized commands to substations. Port 20000 is a primary reconnaissance target for similar attacks.
- **Zero authentication** — DNP3 has minimal security in its original specification. Authentication (Secure Authentication v5) is an optional extension that is rarely deployed. Most DNP3 devices accept any command from any source IP. There is no encryption, no access control, and no logging in the base protocol.
- **Water/wastewater SCADA** — DNP3 is also deployed in municipal water systems, controlling pumps, valves, chemical dosing, and monitoring tank levels. Compromised DNP3 endpoints can:
  - Shut down water supply
  - Overdose treatment chemicals (chlorine, fluoride)
  - Manipulate pressure to cause pipe bursts or contamination
  - Disable alarms and monitoring
- **Oil and gas pipelines** — DNP3 is used in pipeline SCADA to control pumps, compressors, and valve actuators. Unauthorized access can cause pipeline shutdowns, overpressure events, or safety system bypasses.
- **Nation-state targeting** — APT groups (Sandworm, Dragonfly/Energetic Bear, APT33) specifically target DNP3-enabled infrastructure for espionage and sabotage preparation. Shodan indexes thousands of exposed DNP3 devices globally.
- **ICS honeypot and reconnaissance** — Security researchers deploy DNP3 honeypots on port 20000 to study ICS attack patterns. Attackers scan for DNP3 to map critical infrastructure, identify vulnerable firmware, and test command injection payloads.

Port 20000 is one of the most sensitive and heavily-protected ports in critical infrastructure. Exposing DNP3 to the internet is a catastrophic misconfiguration that provides nation-state adversaries with direct access to electric grid, water system, and pipeline control infrastructure.

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

#### Port 34567 — XMEye (XMEye / Generic DVR Clone Protocol)

**Banner**: 20-byte binary header + JSON payload

```
Header (20 bytes):
0xFF 0x00 0x00 0x00  // Magic bytes (XMEye protocol signature)
0xE8 0x03 0x00 0x00  // Message type 0x03E8 (1000 decimal, little-endian) = login response
0x00 0x00 0x00 0x00  // Reserved
0x53 0x00 0x00 0x00  // Payload length (83 bytes, little-endian)
0x00 0x00 0x00 0x00  // Session ID placeholder
0x00 0x00 0x00 0x00  // Sequence number

JSON Payload (83 bytes):
{"AlarmState":"","DeviceType":"DVR","Ret":100,"SessionID":"0x00000001"}
```

**Purpose**: Mimics the login challenge response of XMEye firmware, a Hikvision-derivative DVR/NVR protocol used in millions of cheap security camera systems. The response structure:
- 20-byte binary header with magic `0xFF 0x00 0x00 0x00` (XMEye protocol identifier)
- Message type `0x03E8` (1000 = login response in XMEye protocol)
- JSON payload with `Ret:100` (return code 100 = "authentication required" in XMEye protocol)
- SessionID field (initially `0x00000001` for unauthenticated connections)

**Why it's convincing**: XMEye is Hikvision-derivative firmware used in countless white-label DVR/NVR clones sold under hundreds of brand names (Zosi, Annke, Reolink, Sannce, Zmodo, Jooan, and literally hundreds more). The 20-byte header + JSON-over-TCP structure is the exact protocol format these devices use. The magic bytes `0xFF 0x00 0x00 0x00` and message type `0x03E8` are the fingerprints reconnaissance tools use to identify XMEye devices. The `Ret:100` response code ("authentication required") is more realistic than a successful login, as it indicates the device is secured but present.

**Why this port is targeted**: Port 34567 is one of the MOST heavily-scanned ports on the entire internet:
- **Massive deployed device count** — tens of millions (possibly over 100 million) XMEye-based DVRs and NVRs are deployed worldwide. This is one of the largest IoT device categories in existence. Every cheap "8-channel DVR" or "16-channel NVR" sold on Amazon, eBay, AliExpress, and through security camera installers likely uses XMEye firmware.
- **Universal default credentials** — XMEye devices overwhelmingly ship with default credentials: `admin` (blank password), `admin`/`admin`, `admin`/`12345`, `admin`/`123456`, or `888888`/`888888`. Credential stuffing attacks on port 34567 have an extraordinarily high success rate.
- **Critical vulnerabilities** — XMEye firmware is riddled with security flaws: authentication bypass (CVE-2018-9995 — allows complete device access without credentials), backdoor accounts (hardcoded `default`/`tluafed` credentials in some versions), command injection, buffer overflows, and firmware backdoors. Many of these vulnerabilities have NEVER been patched in deployed devices.
- **Botnet recruitment** — Mirai variants and IoT botnets (Moobot, Gafgyt, Kaiten) specifically target port 34567 for recruitment. Compromised XMEye DVRs are used for DDoS attacks, cryptomining, proxying, and network infiltration.
- **Surveillance access** — attackers gain access to all connected camera feeds (often 4, 8, 16, or 32 cameras per DVR), recorded footage, motion detection zones, and camera settings. This provides surveillance of homes, businesses, warehouses, parking lots, and other private spaces.
- **Lateral movement** — DVRs are typically installed on the main network (not isolated VLANs) and have network access to internal systems, making them prime pivot points for ransomware and lateral movement attacks.
- **Data exfiltration** — recorded footage is exfiltrated and sold (or used for blackmail). Business surveillance footage, home security cameras, and even baby monitors have been compromised and published.
- **Persistent backdoors** — attackers install persistent malware in firmware or startup scripts, maintaining access even after password changes or system reboots.

Port 34567 is arguably the single largest IoT security disaster category on the internet. The combination of massive deployment numbers + universal default credentials + unpatched critical vulnerabilities + single protocol makes this port a primary target for every IoT botnet operator and surveillance hacker.

---

#### Port 37777 — Dahua (Dahua DVR/NVR Proprietary Protocol)

**Banner**: 20-byte Dahua challenge packet

```
0xFF 0x01 0x00 0x00  // Magic bytes (Dahua protocol signature: 0xFF 0x01)
0x00 0x00 0x00 0x00  // Session ID (0x00000000 = new/unauthenticated session)
0x00 0x00 0x00 0x00  // Sequence number (0x00000000 = first packet in session)
0x00 0x00 0x00 0x00  // Reserved / padding
0x00 0x00 0x00 0x00  // Result code (0x00000000 = success/ready)
```

**Purpose**: Mimics the challenge packet that Dahua DVR and NVR devices send when a client initiates a TCP connection. The response structure:
- Magic bytes `0xFF 0x01` — the Dahua protocol signature (this is THE fingerprint scanners look for)
- Session ID of `0x00000000` (indicates a new, unauthenticated session)
- Sequence number `0x00000000` (first packet in the session handshake)
- Result code `0x00000000` (success — the device is ready to proceed with authentication)

**Why it's convincing**: Dahua is one of the world's largest security camera and DVR manufacturers (second only to Hikvision). The magic bytes `0xFF 0x01` at the start of every Dahua protocol packet are the exact fingerprint that Shodan, Censys, and reconnaissance tools use to identify Dahua devices. This 20-byte challenge packet is what real Dahua DVRs send immediately after accepting a TCP connection on port 37777, before any authentication negotiation begins.

**Why this port is targeted**: Port 37777 is one of the most CRITICAL and heavily-exploited IoT ports on the internet:
- **CVE-2021-33044 and the Dahua credential bypass epidemic** — CVE-2021-33044 is an authentication bypass vulnerability affecting hundreds of Dahua DVR/NVR/IP camera models. Attackers can bypass authentication entirely and gain admin access without knowing credentials. This vulnerability (and related bypasses CVE-2022-30564, CVE-2022-30563) remains UNPATCHED on millions of deployed Dahua devices. Port 37777 is the attack surface for these exploits.
- **Massive deployment scale** — Dahua devices are deployed in commercial security systems, government facilities, critical infrastructure, retail stores, warehouses, and residential installations worldwide. Dahua has 30%+ global market share in the DVR/NVR market.
- **Default credentials** — like Hikvision, Dahua devices ship with default credentials (`admin`/`admin`, `admin`/blank, `888888`/`888888`). Most deployed devices still use these defaults.
- **Nation-state targeting** — the U.S. government banned Dahua devices from federal installations (NDAA Section 889) due to cybersecurity and surveillance concerns. Despite this, millions of Dahua devices remain deployed in critical infrastructure. Port 37777 is actively scanned by nation-state actors seeking access to surveillance networks.
- **Botnet recruitment** — IoT botnets specifically target port 37777 with both credential stuffing and CVE-2021-33044 exploits. Compromised Dahua devices are recruited into DDoS swarms.
- **Surveillance hijacking** — attackers gain access to live camera feeds, recorded footage, alarm/motion detection settings, and network configuration. Dahua systems often control 4–64 cameras per DVR/NVR, providing extensive surveillance access.
- **Supply chain concerns** — Dahua devices have been implicated in supply chain security concerns due to potential backdoors and data exfiltration to Chinese servers. Port 37777 communication has been observed initiating outbound connections to Dahua cloud services without user consent.
- **Firmware persistence** — attackers upload malicious firmware or modify startup scripts to maintain persistent access. Dahua's firmware update mechanism is poorly secured, allowing unauthorized firmware installation via port 37777.

Port 37777 represents one of the highest-risk attack surfaces in the IoT ecosystem due to the combination of critical unpatched vulnerabilities + massive deployment scale + government/nation-state interest + botnet targeting. The magic bytes `0xFF 0x01` are instantly recognizable to every IoT scanner on the internet.

---

#### Port 44818 — EtherNet/IP (CIP / Rockwell/Allen-Bradley PLCs)

**Banner**: 65-byte List Identity reply

**Purpose**: Sends a complete EtherNet/IP List Identity response that Allen-Bradley/Rockwell Automation PLCs send when queried:
- Command: `0x0063` (List Identity Reply)
- Session handle: `0x00000000` (connectionless unconnected message)
- Status: `0x00000000` (success)
- Sender context: 8 bytes (echo of request context)
- Options: `0x00000000`
- Encapsulation protocol version: `0x0001`
- Identity item type code: `0x000C` (CIP Identity)
- Identity item length: 40 bytes
- Device identity:
  - Vendor ID: `0x0001` (Rockwell Automation / Allen-Bradley)
  - Device type: `0x0002` (Communications Adapter)
  - Product code: `0x0089` (137 decimal = 1756-ENBT/A ControlLogix Ethernet Bridge)
  - Revision: `3.5` (major.minor firmware revision)
  - Status: `0x0060` (Operational state, configured)
  - Serial number: `0x12345678` (device serial number)
  - Product name: `1756-ENBT/A` (18 characters, counted string)
  - State: `0xFF` (operational)

**Why it's convincing**: EtherNet/IP is the industrial Ethernet protocol used by Allen-Bradley (Rockwell Automation) PLCs, the dominant automation platform in North American manufacturing. The List Identity command is the standard discovery/enumeration method that SCADA systems, HMI software, and reconnaissance tools use to identify EtherNet/IP devices. The response structure exactly matches the CIP (Common Industrial Protocol) specification. The vendor ID `0x0001` (Rockwell Automation) combined with device type `0x0002` (Communications Adapter) and product code `0x0089` (1756-ENBT/A) is the exact fingerprint that Shodan's "ethernetip" search filter looks for. The 1756-ENBT/A is the Ethernet/IP bridge module for ControlLogix PLCs, one of the most widely deployed industrial controllers globally.

**Why this port is targeted**: Port 44818 is THE primary attack surface for North American industrial automation:
- **ControlLogix/CompactLogix dominance** — Allen-Bradley ControlLogix, CompactLogix, and MicroLogix PLCs are the standard in automotive manufacturing, food/beverage processing, pharmaceutical production, and discrete manufacturing. Port 44818 is the default EtherNet/IP port for these systems. An exposed port 44818 indicates direct access to production control logic.
- **Zero authentication** — EtherNet/IP has NO authentication in its base specification. Any client can:
  - Read PLC tags (variables, I/O states, setpoints, counters)
  - Write PLC tags to change process parameters or outputs
  - Upload ladder logic programs (proprietary manufacturing processes, trade secrets)
  - Download modified programs (sabotage, backdoors)
  - Start/stop the PLC CPU
  - Clear faults and alarms
  - Reset the controller
- **Critical infrastructure and manufacturing** — ControlLogix PLCs are deployed in: automotive assembly lines (robotics, welding, painting), chemical batch processing, water treatment (pumps, valves, dosing), power generation (turbine controls, boiler management), pharmaceutical clean rooms, food production (mixing, filling, packaging). Compromised EtherNet/IP endpoints can:
  - Halt production lines (downtime costs thousands to millions per hour)
  - Modify product recipes or formulations (quality sabotage, safety violations)
  - Disable safety interlocks (causing equipment damage or worker injury)
  - Exfiltrate intellectual property (recipes, process parameters, control algorithms)
- **Shodan indexing** — Shodan actively scans for port 44818 and identifies exposed EtherNet/IP devices by vendor ID and product code. Thousands of PLCs are discoverable via searches like `port:44818 country:US` or `"Product Name: 1756-ENBT"`. Each indexed PLC is a high-value target.
- **Ransomware targeting** — Industrial ransomware (Ryuk, LockerGoga, EKANS/SNAKE) specifically targets OT environments. EKANS malware contains a hardcoded list of EtherNet/IP-related process names to terminate before encrypting. Compromised EtherNet/IP devices are used to map OT networks and identify critical assets before ransomware deployment.
- **Nation-state espionage and sabotage** — APT groups (Dragonfly/Energetic Bear, APT33, Triton/Trisis operators) target EtherNet/IP-enabled manufacturing and critical infrastructure for espionage (steal production data, supply chain intelligence) and sabotage preparation (pre-position backdoors, map process control logic).
- **Supply chain attacks** — Compromised PLCs can be used to sabotage manufactured products (insert defects, weaken materials, violate tolerances) or steal product designs and manufacturing processes for counterfeit production or competitive intelligence.

Port 44818 is the single most important industrial protocol port for North American manufacturing security. An exposed EtherNet/IP device is a catastrophic misconfiguration equivalent to publishing production control credentials and intellectual property to the internet.

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
| 47808 | BACnet | Building Automation and Control Networks |

**Why these ports**:
- **DNS (53)**: Used by DNS amplification attacks and reconnaissance
- **NTP (123)**: Target of NTP amplification DDoS attacks
- **SNMP (161)**: Common target for device enumeration and exploitation
- **MSSQL-Mon (1434)**: Database reconnaissance and SQL Slammer-style attacks. The MSSQL Browser/Monitor Service on UDP 1434 is queried to discover SQL Server instances on the network. Scanners hit this port alongside TCP 1433 to enumerate database servers. By capturing without responding, webTraffik logs reconnaissance attempts without participating in amplification attacks or revealing database information.
- **SSDP (1900)**: Used by UPnP exploits and device discovery scans
- **SIP (5060)**: VoIP service discovery and SIP scanning
- **Ethereum-Disc (30303)**: Ethereum's UDP-based node discovery protocol (discv4 and the newer discv5). Ethereum nodes broadcast UDP discovery ping packets to find peers and maintain the distributed hash table (DHT) of node information. Bots and network mappers send discovery packets to enumerate the Ethereum P2P network. This port complements TCP 30303 (RLPx encrypted transport) for complete Ethereum network reconnaissance capture.
- **BACnet (47808)**: Building Automation and Control Networks protocol, used for HVAC, elevators, lighting, fire safety, and access control systems in commercial buildings. BACnet devices communicate via UDP broadcasts (Who-Is queries, I-Am announcements, COV notifications). Shodan has indexed hundreds of thousands of exposed BACnet devices globally. Attackers target BACnet to: map building automation infrastructure, identify vulnerable HVAC controllers (exploited for ransomware delivery and lateral movement), manipulate HVAC setpoints (cause discomfort or equipment damage), disable fire safety systems, or hijack access control (unlock doors, disable alarms). Port 47808 is capture-only — real BACnet devices respond to Who-Is broadcasts, but logging the reconnaissance attempts without responding is sufficient to track scanning activity.

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

**Last synchronized with**: `services.go` as of the current codebase state (60 TCP services, 8 UDP services, 1 Minecraft service, 17 HTTP ports)
