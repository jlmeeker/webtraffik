package services

import (
	"sort"
	"strconv"
	"strings"
)

// tcpServiceNames maps every port the app listens on to a display name.
// This is the canonical source used by PortServiceName(), PortsForService(),
// and the /api/services dropdown. It covers TCP service ports, UDP ports,
// HTTP capture ports, and the Minecraft port.
var tcpServiceNames = map[int]string{
	// Special (no port — protocol-level events)
	0: "ICMP",
	// TCP service ports (banner emulation)
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	102:   "S7comm",
	110:   "POP3",
	135:   "RPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	502:   "Modbus",
	554:   "RTSP",
	631:   "IPP",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	1723:  "PPTP",
	2082:  "cPanel",
	2083:  "cPanel SSL",
	2375:  "Docker",
	3283:  "ARD",
	3306:  "MySQL",
	3389:  "RDP",
	4444:  "Metasploit",
	4899:  "Radmin",
	5432:  "PostgreSQL",
	5555:  "ADB",
	5900:  "VNC",
	5985:  "WinRM",
	5986:  "WinRM SSL",
	6000:  "X11",
	6379:  "Redis",
	6443:  "Kubernetes API",
	6667:  "IRC",
	8291:  "Winbox",
	8443:  "HTTPS alt",
	8728:  "RouterOS API",
	8729:  "RouterOS SSL",
	8899:  "Hikvision Cam",
	9100:  "Printer",
	9200:  "Elasticsearch",
	11211: "Memcached",
	18789: "OpenClaw",
	20000: "DNP3",
	27017: "MongoDB",
	34567: "DVR (XMEye)",
	37777: "DVR (Dahua)",
	44818: "EtherNet/IP",
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
	53:    "DNS",
	123:   "NTP",
	161:   "SNMP",
	1434:  "MSSQL Browser",
	1900:  "SSDP",
	5060:  "SIP",
	47808: "BACnet",
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

// serviceEntry describes a banner-only TCP service the app impersonates.
type serviceEntry struct {
	Port   int
	Banner func() []byte // returns the bytes to write immediately after accept
}

// ── Port registry ─────────────────────────────────────────────────────────────
//
// The registry is the single source of truth for every port webTraffik binds.
// The firewall port sets (`webtraffik ports`), the /api/services listing, the
// metrics labels and the Run() listener set are all derived from it.

// Kind selects how a port is served.
type Kind uint8

const (
	KindHTTP   Kind = iota + 1 // plain HTTP honeypot
	KindHTTPS                  // TLS-terminating HTTP honeypot (JA3/JA4 capture)
	KindBanner                 // send a canned banner, read a little, close
	KindCustom                 // interactive protocol emulator (see customHandlers)
	KindUDP                    // datagram capture
)

// Spec describes one listener.
type Spec struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // "tcp" or "udp"
	Name  string `json:"name"`
	Kind  Kind   `json:"kind"`
}

// httpPorts are the plain-HTTP capture ports.
var httpPorts = []int{
	80, 8080, 8000, 8008, 8081, 8088, 8090, 8888,
	3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090,
}

// tlsPorts terminate TLS and serve the HTTP honeypot.
var tlsPorts = []int{443, 8443}

// customTCPPorts have interactive emulators; Env.customHandlers must provide a
// handler for each (enforced by a test).
var customTCPPorts = []int{21, 22, 23, 25, 110, 5900, 6379, 9735, 25565}

// nameByPort is the precomputed port → service name lookup.
var nameByPort = func() map[string]string {
	m := make(map[string]string, len(tcpServiceNames))
	for p, n := range tcpServiceNames {
		m[strconv.Itoa(p)] = n
	}
	return m
}()

func isIn(list []int, p int) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}

// All returns every listener spec, sorted by port then protocol.
func All() []Spec {
	var specs []Spec
	add := func(port int, proto string, k Kind) {
		specs = append(specs, Spec{Port: port, Proto: proto, Name: tcpServiceNames[port], Kind: k})
	}
	for _, p := range httpPorts {
		add(p, "tcp", KindHTTP)
	}
	for _, p := range tlsPorts {
		add(p, "tcp", KindHTTPS)
	}
	for _, p := range customTCPPorts {
		add(p, "tcp", KindCustom)
	}
	for _, svc := range tcpServices {
		if isIn(httpPorts, svc.Port) || isIn(tlsPorts, svc.Port) || isIn(customTCPPorts, svc.Port) {
			continue
		}
		add(svc.Port, "tcp", KindBanner)
	}
	for _, p := range udpServicePorts {
		add(p, "udp", KindUDP)
	}
	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Port != specs[j].Port {
			return specs[i].Port < specs[j].Port
		}
		return specs[i].Proto < specs[j].Proto
	})
	return specs
}

// Ports returns the sorted, de-duplicated ports for proto ("tcp" or "udp"),
// excluding any in disabled.
func Ports(proto string, disabled map[int]bool) []int {
	var out []int
	seen := map[int]bool{}
	for _, s := range All() {
		if s.Proto == proto && !disabled[s.Port] && !seen[s.Port] {
			seen[s.Port] = true
			out = append(out, s.Port)
		}
	}
	return out
}

// PortKey identifies a listener by protocol and port.
type PortKey struct {
	Proto string // "tcp" or "udp"
	Port  int
}

// ListenedPorts is the set of (protocol, port) pairs that Go listeners serve.
// Protocol matters: TCP/443 has a listener but UDP/443 (QUIC) does not.
func ListenedPorts(disabled map[int]bool) map[PortKey]bool {
	m := map[PortKey]bool{}
	for _, s := range All() {
		if !disabled[s.Port] {
			m[PortKey{s.Proto, s.Port}] = true
		}
	}
	return m
}

// PortServiceName returns a human-readable service name for a port string,
// or the port itself when unknown.
func PortServiceName(port string) string {
	if n, ok := nameByPort[port]; ok {
		return n
	}
	return port
}

// PortsForService returns all port number strings whose service name matches
// the given name (case-insensitive). Used by the history query filter.
func PortsForService(serviceName string) []string {
	var result []string
	for p, name := range tcpServiceNames {
		if strings.EqualFold(name, serviceName) {
			result = append(result, strconv.Itoa(p))
		}
	}
	sort.Strings(result)
	return result
}

// AllServiceNames returns a map of service name → ports, used by /api/services.
func AllServiceNames() map[string][]int {
	seen := map[string][]int{}
	for port, name := range tcpServiceNames {
		seen[name] = append(seen[name], port)
	}
	for _, ports := range seen {
		sort.Ints(ports)
	}
	return seen
}
