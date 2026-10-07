package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseConfigPrecedence(t *testing.T) {
	t.Setenv("WEBTRAFFIK_DASHBOARD_PASS", "")
	p := writeCfg(t, "capture-mode: go-only\nretention-days: 7\ndashboard-listen: \":9000\"\n")

	cfg, err := parseConfig([]string{"-config", p})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CaptureMode != "go-only" || cfg.RetentionDays != 7 || cfg.MaxConns != 4096 {
		t.Errorf("file over default failed: %+v", cfg)
	}
	if cfg.MgmtPorts != "9000,22" {
		t.Errorf("mgmt ports should follow dashboard port, got %q", cfg.MgmtPorts)
	}

	cfg, err = parseConfig([]string{"-config=" + p, "-capture-mode=hybrid", "-retention-days=0"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CaptureMode != "hybrid" || cfg.RetentionDays != 0 {
		t.Errorf("flag over file failed: %+v", cfg)
	}
}

func TestConfigRejectsUnknownKeys(t *testing.T) {
	p := writeCfg(t, "capture-mod: hybrid\n") // typo
	if _, err := parseConfig([]string{"-config", p}); err == nil {
		t.Error("typo'd key must be an error, not silently ignored")
	}
}

func TestDashboardPassword(t *testing.T) {
	if _, err := resolveDashboardPass(Config{DashboardUser: "u"}); err == nil {
		t.Error("user without password must fail")
	}
	f := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(f, []byte("hunter2\n"), 0o600)
	if pw, err := resolveDashboardPass(Config{DashboardUser: "u", DashboardPassFile: f}); err != nil || pw != "hunter2" {
		t.Errorf("pass file = %q, %v", pw, err)
	}
	if pw, err := resolveDashboardPass(Config{}); err != nil || pw != "" {
		t.Errorf("no auth configured = %q, %v", pw, err)
	}
}

func TestPortsCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := portsCommand([]string{"-proto", "tcp", "-format", "nft", "-disable", "22,80"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := strings.Split(strings.TrimSpace(out.String()), ", ")
	has := func(p string) bool {
		for _, g := range got {
			if g == p {
				return true
			}
		}
		return false
	}
	if has("22") || has("80") || !has("443") || !has("6379") || !has("8080") {
		t.Errorf("tcp ports = %v", got)
	}
	out.Reset()
	if code := portsCommand([]string{"-proto", "udp", "-format", "nft"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "53") {
		t.Errorf("udp ports = %q", out.String())
	}
	if code := portsCommand([]string{"-format", "nft"}, &out, &errb); code == 0 {
		t.Error("nft without -proto must fail")
	}
	out.Reset()
	if code := portsCommand([]string{"-format", "json"}, &out, &errb); code != 0 || !strings.Contains(out.String(), `"proto": "udp"`) {
		t.Errorf("json = %q", out.String())
	}
}

// TestPortsDocInSync fails when docs/PORTS.md drifts from the registry.
// Regenerate with `make docs`.
func TestPortsDocInSync(t *testing.T) {
	var out, errb bytes.Buffer
	if code := portsCommand([]string{"-format", "md"}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "docs", "PORTS.md"))
	if err != nil {
		t.Fatalf("docs/PORTS.md missing: run `make docs` (%v)", err)
	}
	if string(want) != out.String() {
		t.Error("docs/PORTS.md is out of date: run `make docs`")
	}
}
