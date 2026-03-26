package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ── loadConfig ────────────────────────────────────────────────────────────────

func TestLoadConfig_MissingFile(t *testing.T) {
	cfg, err := loadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if cfg != (Config{}) {
		t.Fatalf("expected zero Config for missing file, got: %+v", cfg)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	yaml := `
disable-ports: "22,80"
disable-rgeo: true
capture-mode: ebpf-only
ebpf-iface: eth1
mgmt-ports: "8999,2222"
mgmt-allow-file: /etc/webtraffik/allow.txt
`
	f := writeTempConfig(t, yaml)

	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DisablePorts != "22,80" {
		t.Errorf("DisablePorts: want %q, got %q", "22,80", cfg.DisablePorts)
	}
	if !cfg.DisableRgeo {
		t.Error("DisableRgeo: want true, got false")
	}
	if cfg.CaptureMode != "ebpf-only" {
		t.Errorf("CaptureMode: want %q, got %q", "ebpf-only", cfg.CaptureMode)
	}
	if cfg.EBPFIface != "eth1" {
		t.Errorf("EBPFIface: want %q, got %q", "eth1", cfg.EBPFIface)
	}
	if cfg.MgmtPorts != "8999,2222" {
		t.Errorf("MgmtPorts: want %q, got %q", "8999,2222", cfg.MgmtPorts)
	}
	if cfg.MgmtAllowFile != "/etc/webtraffik/allow.txt" {
		t.Errorf("MgmtAllowFile: want %q, got %q", "/etc/webtraffik/allow.txt", cfg.MgmtAllowFile)
	}
}

func TestLoadConfig_PartialYAML(t *testing.T) {
	// Only some fields set — unset fields must remain zero.
	yaml := `
capture-mode: go-only
`
	f := writeTempConfig(t, yaml)

	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CaptureMode != "go-only" {
		t.Errorf("CaptureMode: want %q, got %q", "go-only", cfg.CaptureMode)
	}
	// Unset fields should be zero values.
	if cfg.DisablePorts != "" {
		t.Errorf("DisablePorts: want empty, got %q", cfg.DisablePorts)
	}
	if cfg.DisableRgeo {
		t.Error("DisableRgeo: want false, got true")
	}
	if cfg.EBPFIface != "" {
		t.Errorf("EBPFIface: want empty, got %q", cfg.EBPFIface)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	f := writeTempConfig(t, ":\tinvalid: yaml: {{{{")

	_, err := loadConfig(f)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_EmptyFile(t *testing.T) {
	f := writeTempConfig(t, "")

	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if cfg != (Config{}) {
		t.Fatalf("expected zero Config for empty file, got: %+v", cfg)
	}
}

// ── resolveConfigPath ─────────────────────────────────────────────────────────

func TestResolveConfigPath_ExplicitPath(t *testing.T) {
	// Explicit path is returned verbatim, even if the file doesn't exist.
	got := resolveConfigPath("/explicit/path/config.yaml")
	if got != "/explicit/path/config.yaml" {
		t.Errorf("want %q, got %q", "/explicit/path/config.yaml", got)
	}
}

func TestResolveConfigPath_NoFileFound(t *testing.T) {
	// Override defaultConfigPaths with a non-existent path for this test.
	orig := defaultConfigPaths
	defaultConfigPaths = []string{"/nonexistent/config.yaml"}
	defer func() { defaultConfigPaths = orig }()

	got := resolveConfigPath("")
	if got != "" {
		t.Errorf("want empty string when no file exists, got %q", got)
	}
}

func TestResolveConfigPath_DefaultFileExists(t *testing.T) {
	f := writeTempConfig(t, "capture-mode: hybrid\n")

	orig := defaultConfigPaths
	defaultConfigPaths = []string{f}
	defer func() { defaultConfigPaths = orig }()

	got := resolveConfigPath("")
	if got != f {
		t.Errorf("want %q, got %q", f, got)
	}
}

func TestResolveConfigPath_ExplicitOverridesDefault(t *testing.T) {
	// Even if a default path exists, explicit path wins.
	f := writeTempConfig(t, "capture-mode: hybrid\n")

	orig := defaultConfigPaths
	defaultConfigPaths = []string{f}
	defer func() { defaultConfigPaths = orig }()

	explicit := "/my/custom/config.yaml"
	got := resolveConfigPath(explicit)
	if got != explicit {
		t.Errorf("want %q, got %q", explicit, got)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// writeTempConfig writes content to a temp file and returns its path.
// The file is cleaned up automatically when the test ends.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return f
}
