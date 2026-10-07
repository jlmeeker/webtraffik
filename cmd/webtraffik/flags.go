package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"webtraffik/internal/services"
)

var errHelp = errors.New("help requested")

// prescanConfigPath finds -config / --config in args without invoking the flag
// package, because the config file supplies defaults for the other flags.
func prescanConfigPath(args []string) string {
	path := ""
	for i, arg := range args {
		switch {
		case arg == "-config" || arg == "--config":
			if i+1 < len(args) {
				path = args[i+1]
			}
		case strings.HasPrefix(arg, "-config="):
			path = strings.TrimPrefix(arg, "-config=")
		case strings.HasPrefix(arg, "--config="):
			path = strings.TrimPrefix(arg, "--config=")
		}
	}
	return path
}

// parseConfig resolves defaults ← config file ← environment ← CLI flags.
func parseConfig(args []string) (Config, error) {
	cfg := defaultConfig()
	if p := resolveConfigPath(prescanConfigPath(args)); p != "" {
		if err := loadConfigInto(p, &cfg); err != nil {
			return cfg, fmt.Errorf("config %q: %w", p, err)
		}
	}
	if v := os.Getenv("WEBTRAFFIK_DASHBOARD_PASS"); v != "" && cfg.DashboardPass == "" {
		cfg.DashboardPass = v
	}

	fs := flag.NewFlagSet("webtraffik", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := &cfg
	fs.String("config", "", "Path to YAML config file (default /etc/webtraffik/config.yaml if present)")
	fs.StringVar(&c.CaptureMode, "capture-mode", c.CaptureMode, `"hybrid" (eBPF bans + Go listeners), "ebpf-only", or "go-only"`)
	fs.StringVar(&c.EBPFIface, "ebpf-iface", c.EBPFIface, "interface for XDP attach (default: auto-detect from default route)")
	fs.StringVar(&c.MgmtPorts, "mgmt-ports", c.MgmtPorts, "comma-separated ports that bypass eBPF bans/telemetry (default: dashboard port and 22)")
	fs.StringVar(&c.MgmtAllowFile, "mgmt-allow-file", c.MgmtAllowFile, "file of IPs (one per line) that bypass eBPF bans; reloaded on SIGHUP")
	fs.StringVar(&c.DisablePorts, "disable-ports", c.DisablePorts, "comma-separated ports to skip binding (update your firewall too)")
	fs.IntVar(&c.MaxConns, "max-conns", c.MaxConns, "maximum concurrent emulated connections")
	fs.StringVar(&c.DashboardListen, "dashboard-listen", c.DashboardListen, "dashboard listen address, e.g. :8999 or 127.0.0.1:8999")
	fs.StringVar(&c.DashboardUser, "dashboard-user", c.DashboardUser, "dashboard HTTP Basic username (enables auth)")
	fs.StringVar(&c.DashboardPass, "dashboard-pass", c.DashboardPass, "dashboard password (prefer -dashboard-pass-file or $WEBTRAFFIK_DASHBOARD_PASS)")
	fs.StringVar(&c.DashboardPassFile, "dashboard-pass-file", c.DashboardPassFile, "file containing the dashboard password")
	fs.StringVar(&c.AllowedOrigins, "allowed-origins", c.AllowedOrigins, "extra Origin hosts accepted by the dashboard (reverse proxy names)")
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "directory for the database, geo files and host keys (default: working directory)")
	fs.IntVar(&c.RetentionDays, "retention-days", c.RetentionDays, "delete events older than N days (0 = keep forever)")
	fs.StringVar(&c.ExportJSONL, "export-jsonl", c.ExportJSONL, "append every event as a JSON line to this file")
	fs.IntVar(&c.ExportMaxMB, "export-max-mb", c.ExportMaxMB, "rotate the JSONL export at this size in MB")
	fs.BoolVar(&c.EnrichRDNS, "enrich-rdns", c.EnrichRDNS, "reverse-DNS source addresses to recognise research scanners")
	fs.StringVar(&c.GreyNoiseKey, "greynoise-key", c.GreyNoiseKey, "GreyNoise community API key (optional enrichment)")
	fs.StringVar(&c.AbuseIPDBKey, "abuseipdb-key", c.AbuseIPDBKey, "AbuseIPDB API key (optional enrichment)")
	fs.StringVar(&c.PublicIP, "public-ip", c.PublicIP, `this host's public IP (default: auto-discover; "none" to skip)`)
	fs.BoolVar(&c.DisableRgeo, "disable-rgeo", c.DisableRgeo, "skip the rgeo city fallback (saves startup time on slow hardware)")
	fs.BoolVar(&c.DisableASN, "disable-asn", c.DisableASN, "skip ASN enrichment")
	fs.StringVar(&c.GeoCityURL, "geo-city-url", c.GeoCityURL, "download URL for GeoLite2-City.mmdb")
	fs.StringVar(&c.GeoASNURL, "geo-asn-url", c.GeoASNURL, "download URL for GeoLite2-ASN.mmdb")
	fs.StringVar(&c.GeoCitySHA256, "geo-city-sha256", c.GeoCitySHA256, "expected SHA-256 of the City database download")
	fs.StringVar(&c.GeoRefresh, "geo-refresh", c.GeoRefresh, `how often to refresh the geo databases (e.g. "168h"; "0" disables)`)
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug, info, warn or error")
	fs.StringVar(&c.LogFormat, "log-format", c.LogFormat, "text or json")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: webtraffik [flags]\n       webtraffik ports [-proto tcp|udp|all] [-format nft|csv|json] [-disable 22,80]\n       webtraffik version\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, errHelp
		}
		return cfg, err
	}
	if cfg.MgmtPorts == "" {
		cfg.MgmtPorts = defaultMgmtPorts(cfg.DashboardListen)
	}
	return cfg, nil
}

// defaultMgmtPorts is the dashboard port plus SSH.
func defaultMgmtPorts(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil && port != "" {
		return port + ",22"
	}
	return "8999,22"
}

func setupLogging(level, format string) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	o := &slog.HandlerOptions{Level: lv}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, o)
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(os.Stderr, o)
	}
	// Also routes the standard "log" package (used by a few dependencies)
	// through the same handler.
	slog.SetDefault(slog.New(h))
}

func resolveDashboardPass(cfg Config) (string, error) {
	if cfg.DashboardPassFile != "" {
		b, err := os.ReadFile(cfg.DashboardPassFile)
		if err != nil {
			return "", fmt.Errorf("dashboard-pass-file: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if cfg.DashboardUser != "" && cfg.DashboardPass == "" {
		return "", errors.New("dashboard-user is set but no password was provided (dashboard-pass, dashboard-pass-file or $WEBTRAFFIK_DASHBOARD_PASS)")
	}
	return cfg.DashboardPass, nil
}

func joinPath(dir, name string) string { return filepath.Join(dir, name) }

func splitList(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parsePortList(s string) ([]uint16, error) {
	var out []uint16
	for _, t := range splitList(s) {
		p, err := strconv.ParseUint(t, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("invalid port %q", t)
		}
		out = append(out, uint16(p))
	}
	return out, nil
}

func parsePortSet(s string) (map[int]bool, error) {
	ports, err := parsePortList(s)
	if err != nil {
		return nil, err
	}
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[int(p)] = true
	}
	return m, nil
}

// portsCommand implements `webtraffik ports`, the single source of the port
// sets used by firewall.sh.
func portsCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proto := fs.String("proto", "all", "tcp, udp or all")
	format := fs.String("format", "nft", "nft (comma-separated), csv, json or md (markdown table)")
	disable := fs.String("disable", "", "comma-separated ports to exclude (mirrors -disable-ports)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	disabled, err := parsePortSet(*disable)
	if err != nil {
		fmt.Fprintln(stderr, "ports:", err)
		return 2
	}
	switch *proto {
	case "tcp", "udp":
	case "all":
	default:
		fmt.Fprintln(stderr, "ports: -proto must be tcp, udp or all")
		return 2
	}

	var specs []services.Spec
	for _, s := range services.All() {
		if !disabled[s.Port] && (*proto == "all" || s.Proto == *proto) {
			specs = append(specs, s)
		}
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(specs)
	case "csv":
		for _, s := range specs {
			fmt.Fprintf(stdout, "%d,%s,%s\n", s.Port, s.Proto, s.Name)
		}
	case "md":
		fmt.Fprint(stdout, portsMarkdown(specs))
	case "nft":
		if *proto == "all" {
			fmt.Fprintln(stderr, "ports: -format nft needs -proto tcp or udp")
			return 2
		}
		seen := map[int]bool{}
		var parts []string
		for _, s := range specs {
			if !seen[s.Port] {
				seen[s.Port] = true
				parts = append(parts, strconv.Itoa(s.Port))
			}
		}
		fmt.Fprintln(stdout, strings.Join(parts, ", "))
	default:
		fmt.Fprintln(stderr, "ports: unknown -format", *format)
		return 2
	}
	return 0
}

// portsMarkdown renders the registry as the table in docs/PORTS.md.
func portsMarkdown(specs []services.Spec) string {
	mode := map[services.Kind]string{
		services.KindHTTP:   "HTTP honeypot (nginx lookalike, full request capture)",
		services.KindHTTPS:  "TLS honeypot (JA3/JA4 + HTTP capture)",
		services.KindBanner: "banner",
		services.KindCustom: "interactive emulator",
		services.KindUDP:    "datagram capture (some ports answer minimally)",
	}
	var b strings.Builder
	b.WriteString("<!-- Generated by `webtraffik ports -format md`; do not edit. `make docs` regenerates it. -->\n")
	b.WriteString("# Listening ports\n\n| Port | Proto | Service | Behaviour |\n|-----:|:-----:|---------|-----------|\n")
	for _, s := range specs {
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", s.Port, s.Proto, s.Name, mode[s.Kind])
	}
	return b.String()
}
