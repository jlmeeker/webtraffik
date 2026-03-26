package main

import (
	"errors"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// defaultConfigPaths is the ordered list of paths checked when no -config flag
// is provided. The first file that exists is used; if none exist the app runs
// with pure flag/default values.
var defaultConfigPaths = []string{
	"/etc/webtraffik/config.yaml",
}

// Config holds all configurable settings. Each field maps 1-to-1 with a CLI
// flag. CLI flags always take precedence over config file values.
//
// YAML tags use the same names as the CLI flags (hyphens → same spelling).
type Config struct {
	// DisablePorts is a comma-separated list of ports to skip binding.
	// Equivalent to -disable-ports.
	DisablePorts string `yaml:"disable-ports"`

	// DisableRgeo skips loading the rgeo reverse geocoder.
	// Equivalent to -disable-rgeo.
	DisableRgeo bool `yaml:"disable-rgeo"`

	// CaptureMode selects the capture strategy: "hybrid", "ebpf-only", "go-only".
	// Equivalent to -capture-mode.
	CaptureMode string `yaml:"capture-mode"`

	// EBPFIface is the network interface for XDP attach.
	// Equivalent to -ebpf-iface.
	EBPFIface string `yaml:"ebpf-iface"`

	// MgmtPorts is a comma-separated list of management ports that bypass
	// eBPF ban enforcement and telemetry.
	// Equivalent to -mgmt-ports.
	MgmtPorts string `yaml:"mgmt-ports"`

	// MgmtAllowFile is the path to a file listing allowed management IPs.
	// Equivalent to -mgmt-allow-file.
	MgmtAllowFile string `yaml:"mgmt-allow-file"`
}

// loadConfig reads a YAML config file from path and returns the parsed Config.
// Missing fields in the file are left as zero values (caller applies defaults).
// Returns a zero Config (not an error) if the file does not exist.
func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	log.Printf("config: loaded from %s", path)
	return cfg, nil
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
