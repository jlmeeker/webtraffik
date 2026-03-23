package services

import (
	"fmt"
	"strings"
)

// tcpServiceNames maps every port the app listens on to a display name.
// This is the canonical source used by PortServiceName(), PortsForService(),
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

// PortServiceName returns a human-readable service name for a given port number
// string, used by the history API to annotate events.
func PortServiceName(port string) string {
	for p, name := range tcpServiceNames {
		if fmt.Sprintf("%d", p) == port {
			return name
		}
	}
	return port
}

// PortsForService returns all port number strings whose service name matches
// the given name (case-insensitive). Used by the history query filter.
func PortsForService(serviceName string) []string {
	upper := strings.ToUpper(serviceName)
	var result []string
	for p, name := range tcpServiceNames {
		if strings.ToUpper(name) == upper {
			result = append(result, fmt.Sprintf("%d", p))
		}
	}
	return result
}

// AllServiceNames returns a map of service name → list of ports,
// aggregated from tcpServiceNames. Used by the /api/services endpoint.
func AllServiceNames() map[string][]int {
	seen := map[string][]int{}
	for port, name := range tcpServiceNames {
		seen[name] = append(seen[name], port)
	}
	return seen
}
