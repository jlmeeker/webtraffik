package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"webtraffik/internal/geo"
)

// defaultConfigPaths is the ordered list of paths checked when no -config flag
// is provided. The first file that exists is used; if none exist the app runs
// with pure flag/default values.
var defaultConfigPaths = []string{
	"/etc/webtraffik/config.yaml",
}

// Config holds all configurable settings. Each field maps 1-to-1 with a CLI
// flag of the same name. Precedence: CLI flag > config file > default.
type Config struct {
	// ── capture ───────────────────────────────────────────────────────────────
	CaptureMode   string `yaml:"capture-mode"`    // "hybrid", "ebpf-only", "go-only"
	EBPFIface     string `yaml:"ebpf-iface"`      // network interface for XDP attach
	MgmtPorts     string `yaml:"mgmt-ports"`      // ports that bypass eBPF bans/telemetry
	MgmtAllowFile string `yaml:"mgmt-allow-file"` // IPs that bypass eBPF bans (SIGHUP reloads)
	DisablePorts  string `yaml:"disable-ports"`   // ports to skip binding
	MaxConns      int    `yaml:"max-conns"`       // concurrent emulated connections

	// ── dashboard ─────────────────────────────────────────────────────────────
	DashboardListen   string `yaml:"dashboard-listen"`
	DashboardUser     string `yaml:"dashboard-user"`
	DashboardPass     string `yaml:"dashboard-pass"`
	DashboardPassFile string `yaml:"dashboard-pass-file"`
	AllowedOrigins    string `yaml:"allowed-origins"` // extra Origin hosts (reverse proxy), comma separated

	// ── data ──────────────────────────────────────────────────────────────────
	DataDir       string `yaml:"data-dir"`       // database, geo files, host keys (default: working dir)
	RetentionDays int    `yaml:"retention-days"` // delete events older than this; 0 keeps everything
	ExportJSONL   string `yaml:"export-jsonl"`   // append events as JSON lines to this file
	ExportMaxMB   int    `yaml:"export-max-mb"`  // rotate the export file at this size
	PublicIP      string `yaml:"public-ip"`      // override auto-discovery; "none" skips it

	// ── geolocation ───────────────────────────────────────────────────────────
	DisableRgeo   bool   `yaml:"disable-rgeo"`
	DisableASN    bool   `yaml:"disable-asn"`
	GeoCityURL    string `yaml:"geo-city-url"`
	GeoASNURL     string `yaml:"geo-asn-url"`
	GeoCitySHA256 string `yaml:"geo-city-sha256"` // pin the City DB download
	GeoRefresh    string `yaml:"geo-refresh"`     // e.g. "168h"; "0" disables refresh

	// ── logging ───────────────────────────────────────────────────────────────
	LogLevel  string `yaml:"log-level"`  // debug, info, warn, error
	LogFormat string `yaml:"log-format"` // text or json
}

// defaultConfig returns the compiled-in defaults.
func defaultConfig() Config {
	return Config{
		CaptureMode:     "hybrid",
		MaxConns:        4096,
		DashboardListen: ":8999",
		RetentionDays:   90,
		ExportMaxMB:     100,
		GeoCityURL:      geo.DefaultCityURL,
		GeoASNURL:       geo.DefaultASNURL,
		GeoRefresh:      "168h",
		LogLevel:        "info",
		LogFormat:       "text",
	}
}

// loadConfig reads a YAML config file from path and returns the parsed Config.
// Missing fields in the file are left as zero values (caller applies defaults).
// Returns a zero Config (not an error) if the file does not exist.
func loadConfig(path string) (Config, error) {
	var cfg Config
	if err := loadConfigInto(path, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// loadConfigInto overlays the YAML file at path onto cfg: keys present in the
// file override cfg, absent keys leave it untouched. A missing file is not an
// error. Unknown keys are rejected so typos do not silently do nothing.
func loadConfigInto(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	overlay := *cfg
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&overlay); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	*cfg = overlay
	slog.Info("config loaded", "path", path)
	return nil
}

// resolveConfigPath returns the config file path to use:
//   - If explicit is non-empty (from -config flag), return it unconditionally.
//   - Otherwise, scan defaultConfigPaths and return the first one that exists.
//   - Returns "" if no file is found (caller skips config loading silently).
func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range defaultConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
