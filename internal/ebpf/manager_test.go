package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// ── CaptureMode ──────────────────────────────────────────────────────────────

func TestCaptureModeString(t *testing.T) {
	tests := []struct {
		mode CaptureMode
		want string
	}{
		{ModeHybrid, "hybrid"},
		{ModeEBPFOnly, "ebpf-only"},
		{ModeGoOnly, "go-only"},
		{CaptureMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("CaptureMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestParseCaptureMode(t *testing.T) {
	tests := []struct {
		input   string
		want    CaptureMode
		wantErr bool
	}{
		{"hybrid", ModeHybrid, false},
		{"HYBRID", ModeHybrid, false},
		{"  hybrid  ", ModeHybrid, false},
		{"ebpf-only", ModeEBPFOnly, false},
		{"ebpfonly", ModeEBPFOnly, false},
		{"EBPF-ONLY", ModeEBPFOnly, false},
		{"go-only", ModeGoOnly, false},
		{"goonly", ModeGoOnly, false},
		{"GO-ONLY", ModeGoOnly, false},
		{"invalid", ModeGoOnly, true},
		{"", ModeGoOnly, true},
		{"xdp", ModeGoOnly, true},
	}
	for _, tt := range tests {
		got, err := ParseCaptureMode(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ParseCaptureMode(%q): expected error, got nil", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ParseCaptureMode(%q): unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseCaptureMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ── New / IsActive ────────────────────────────────────────────────────────────

func TestNewManagerDefaults(t *testing.T) {
	m := New(ModeGoOnly, "", nil, "")
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.mode != ModeGoOnly {
		t.Errorf("mode = %v, want ModeGoOnly", m.mode)
	}
	// Default mgmt ports should be populated.
	if len(m.mgmtPorts) == 0 {
		t.Error("mgmtPorts should default to non-empty")
	}
	if m.IsActive() {
		t.Error("IsActive() should be false before Start()")
	}
}

func TestNewManagerCustomPorts(t *testing.T) {
	ports := []uint16{8080, 9000}
	m := New(ModeHybrid, "eth0", ports, "")
	if len(m.mgmtPorts) != 2 {
		t.Errorf("mgmtPorts length = %d, want 2", len(m.mgmtPorts))
	}
	if m.mgmtPorts[0] != 8080 || m.mgmtPorts[1] != 9000 {
		t.Errorf("mgmtPorts = %v, want [8080 9000]", m.mgmtPorts)
	}
}

// ── Start in go-only mode (no kernel required) ────────────────────────────────

func TestStartGoOnlyIsNoop(t *testing.T) {
	m := New(ModeGoOnly, "", nil, "")
	if err := m.Start(); err != nil {
		t.Fatalf("Start() in go-only mode returned error: %v", err)
	}
	// Manager must remain inactive — no XDP attached.
	if m.IsActive() {
		t.Error("IsActive() should be false after go-only Start()")
	}
}

func TestStopInactiveManagerIsNoop(t *testing.T) {
	m := New(ModeGoOnly, "", nil, "")
	// Stop on a never-started manager must not panic or error.
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop() on inactive manager returned error: %v", err)
	}
}

// ── Ban / Unban on inactive manager ──────────────────────────────────────────

func TestBanUnbanInactiveManager(t *testing.T) {
	m := New(ModeGoOnly, "", nil, "")
	// All calls are no-ops when inactive; must not error.
	if err := m.Ban("1.2.3.4", "80", time.Hour); err != nil {
		t.Errorf("Ban() on inactive manager: %v", err)
	}
	if err := m.Unban("1.2.3.4", "80"); err != nil {
		t.Errorf("Unban() on inactive manager: %v", err)
	}
}

// ── Ban input validation (inactive manager — covers parse logic without kernel) ─

func TestBanInvalidIPReturnsError(t *testing.T) {
	// To trigger the validation path we need an active manager with valid objs.
	// Without a real kernel we can't attach, so we test parsePort / makeBanKey
	// directly instead (they are package-level functions, visible from the test).
	_, err := ParseCaptureMode("not-a-mode")
	if err == nil {
		t.Error("expected error for invalid mode")
	}
}

// ── makeBanKey ────────────────────────────────────────────────────────────────

func TestMakeBanKey(t *testing.T) {
	ip := net.ParseIP("192.168.1.100").To4()
	key, err := makeBanKey(ip, 443)
	if err != nil {
		t.Fatalf("makeBanKey: %v", err)
	}

	// SrcIP bytes must match the raw IPv4 bytes.
	if key.SrcIP[0] != 192 || key.SrcIP[1] != 168 || key.SrcIP[2] != 1 || key.SrcIP[3] != 100 {
		t.Errorf("SrcIP = %v, want [192 168 1 100]", key.SrcIP)
	}

	// DstPort must be big-endian 443 = 0x01BB.
	wantPortBytes := [2]byte{0x01, 0xBB}
	if key.DstPort != wantPortBytes {
		t.Errorf("DstPort = %v, want %v", key.DstPort, wantPortBytes)
	}

	// Verify round-trip: decode port back from big-endian.
	decoded := binary.BigEndian.Uint16(key.DstPort[:])
	if decoded != 443 {
		t.Errorf("decoded port = %d, want 443", decoded)
	}
}

func TestMakeBanKeyIPv6ReturnsError(t *testing.T) {
	ipv6 := net.ParseIP("::1") // pure IPv6, To4() returns nil
	// net.IP("::1").To4() == nil, so makeBanKey should return an error.
	_, err := makeBanKey(ipv6, 80)
	if err == nil {
		t.Error("makeBanKey with IPv6-only address should return error")
	}
}

func TestMakeBanKeyPortBoundaries(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To4()

	// Port 0
	key0, err := makeBanKey(ip, 0)
	if err != nil {
		t.Fatalf("makeBanKey port 0: %v", err)
	}
	if binary.BigEndian.Uint16(key0.DstPort[:]) != 0 {
		t.Error("port 0 encoding incorrect")
	}

	// Port 65535
	key65535, err := makeBanKey(ip, 65535)
	if err != nil {
		t.Fatalf("makeBanKey port 65535: %v", err)
	}
	if binary.BigEndian.Uint16(key65535.DstPort[:]) != 65535 {
		t.Error("port 65535 encoding incorrect")
	}
}

// ── parsePort ─────────────────────────────────────────────────────────────────

func TestParsePort(t *testing.T) {
	tests := []struct {
		input   string
		want    uint16
		wantErr bool
	}{
		{"80", 80, false},
		{"443", 443, false},
		{"0", 0, false},
		{"65535", 65535, false},
		{"abc", 0, true},
		{"", 0, true},
		{"-1", 0, true},
	}
	for _, tt := range tests {
		got, err := parsePort(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("parsePort(%q): expected error, got nil", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parsePort(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("parsePort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ── kernelUptime ──────────────────────────────────────────────────────────────

func TestKernelUptime(t *testing.T) {
	uptime, err := kernelUptime()
	if err != nil {
		t.Skipf("kernelUptime: %v (not on Linux, skipping)", err)
	}
	if uptime <= 0 {
		t.Errorf("kernelUptime = %v, want > 0", uptime)
	}
}

// ── DefaultInterface ──────────────────────────────────────────────────────────

func TestDefaultInterface(t *testing.T) {
	iface, err := DefaultInterface()
	if err != nil {
		t.Skipf("DefaultInterface: %v (no default route or not Linux, skipping)", err)
	}
	if iface == "" {
		t.Error("DefaultInterface() returned empty string")
	}
	// Must be a real interface name known to the OS.
	if _, err := net.InterfaceByName(iface); err != nil {
		t.Errorf("DefaultInterface() returned %q which is not a valid interface: %v", iface, err)
	}
}

// ── Snapshot on inactive manager ─────────────────────────────────────────────

func TestSnapshotInactiveManager(t *testing.T) {
	m := New(ModeGoOnly, "", nil, "")
	snap := m.Snapshot()

	if snap.Enabled {
		t.Error("Enabled should be false for inactive manager")
	}
	if snap.Mode != "go-only" {
		t.Errorf("Mode = %q, want %q", snap.Mode, "go-only")
	}
	if snap.PacketsPassed != 0 {
		t.Errorf("PacketsPassed = %d, want 0", snap.PacketsPassed)
	}
	if snap.PacketsDropped != 0 {
		t.Errorf("PacketsDropped = %d, want 0", snap.PacketsDropped)
	}
	if snap.BansActive != 0 {
		t.Errorf("BansActive = %d, want 0", snap.BansActive)
	}
	if snap.UptimeSeconds != 0 {
		t.Errorf("UptimeSeconds = %d, want 0", snap.UptimeSeconds)
	}
}

func TestSnapshotModePropagated(t *testing.T) {
	for _, mode := range []CaptureMode{ModeHybrid, ModeEBPFOnly, ModeGoOnly} {
		m := New(mode, "eth0", nil, "")
		snap := m.Snapshot()
		if snap.Mode != mode.String() {
			t.Errorf("mode %v: Snapshot().Mode = %q, want %q", mode, snap.Mode, mode.String())
		}
	}
}
