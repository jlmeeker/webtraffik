package ebpf

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// CaptureMode selects the capture strategy at startup.
type CaptureMode int

const (
	// ModeHybrid (default): XDP enforces bans; Go listeners capture traffic
	// and send protocol banners. Best balance of performance and functionality.
	ModeHybrid CaptureMode = iota

	// ModeEBPFOnly: XDP handles all telemetry. No Go net.Listeners are spawned.
	// Maximum performance; service emulation (FTP/SSH banners) unavailable.
	ModeEBPFOnly

	// ModeGoOnly: pure userspace (legacy behavior). eBPF manager is a no-op.
	// Use on non-eBPF systems, old kernels, or for debugging.
	ModeGoOnly
)

// String returns the human-readable name for a CaptureMode.
func (m CaptureMode) String() string {
	switch m {
	case ModeHybrid:
		return "hybrid"
	case ModeEBPFOnly:
		return "ebpf-only"
	case ModeGoOnly:
		return "go-only"
	default:
		return "unknown"
	}
}

// ParseCaptureMode converts a flag string to a CaptureMode.
// Returns ModeGoOnly and an error on unrecognised input.
func ParseCaptureMode(s string) (CaptureMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hybrid":
		return ModeHybrid, nil
	case "ebpf-only", "ebpfonly":
		return ModeEBPFOnly, nil
	case "go-only", "goonly":
		return ModeGoOnly, nil
	default:
		return ModeGoOnly, fmt.Errorf("ebpf: unknown capture mode %q (valid: hybrid, ebpf-only, go-only)", s)
	}
}

// ipKey mirrors the C struct ip_key: a 16-byte address in network order.
// IPv4 addresses are v4-mapped (::ffff:a.b.c.d).
type ipKey struct {
	Addr [16]byte
}

// banKey mirrors the C struct ban_key layout used as the eBPF map key
// (20 bytes). SrcIP is a 16-byte v4-mapped/IPv6 address and DstPort is a
// big-endian uint16, both in network byte order as the XDP program builds
// the key from packet headers.
type banKey struct {
	SrcIP   [16]byte
	DstPort [2]byte
	_       [2]byte // padding to match C struct
}

// banEntry mirrors the C struct ban_entry (8 bytes: one uint64).
type banEntry struct {
	ExpiresAt uint64 // nanoseconds since boot (bpf_ktime_get_ns epoch)
}

// Manager owns the eBPF XDP program lifecycle.
// Zero value is valid; IsActive() returns false until Start() succeeds.
type Manager struct {
	mode      CaptureMode
	iface     string
	mgmtPorts []uint16
	allowFile string

	// Generated types from bpf2go (captureObjects, capturePrograms, captureMaps).
	// These fields are nil until Start() successfully loads the eBPF object.
	objs *captureObjects

	// xdpLink is the kernel link handle returned by link.AttachXDP.
	// Closing it detaches the XDP program.
	xdpLink link.Link

	// eventsReader is the perf.Reader for the events perf array map.
	eventsReader *perf.Reader

	// EventCh streams parsed Events to the application layer.
	// Buffered (256) to absorb bursts. Closed when the reader goroutine exits.
	EventCh chan Event

	stats     statsCache
	startedAt time.Time
	stopCh    chan struct{}
	active    atomic.Bool
}

// New creates a Manager for the given mode, interface, management ports and
// optional allow file.  No kernel state is touched until Start() is called.
//
// iface may be empty to trigger auto-detection via DefaultInterface().
// mgmtPorts defaults to {22, 8999} if nil or empty.
// allowFile may be empty to skip the IP allowlist feature.
func New(mode CaptureMode, iface string, mgmtPorts []uint16, allowFile string) *Manager {
	if len(mgmtPorts) == 0 {
		mgmtPorts = []uint16{22, 8999}
	}
	return &Manager{
		mode:      mode,
		iface:     iface,
		mgmtPorts: mgmtPorts,
		allowFile: allowFile,
		stopCh:    make(chan struct{}),
		EventCh:   make(chan Event, 4096),
	}
}

// IsActive returns true if the XDP program is currently attached.
func (m *Manager) IsActive() bool {
	return m.active.Load()
}

// Start loads the compiled eBPF bytecode, populates maps from configuration,
// attaches the XDP program to the network interface, and begins streaming
// events into m.EventCh.
//
// If the mode is ModeGoOnly, Start() is a no-op and returns nil immediately.
//
// On any attachment failure the function returns a non-nil error; the caller
// should fall back to ModeGoOnly and continue — the application must not
// crash because eBPF is unavailable.
func (m *Manager) Start() error {
	if m.mode == ModeGoOnly {
		log.Printf("ebpf: mode=go-only, skipping eBPF attach")
		return nil
	}

	// Auto-detect the network interface if not specified.
	if m.iface == "" {
		detected, err := DefaultInterface()
		if err != nil {
			return fmt.Errorf("ebpf: auto-detect interface: %w", err)
		}
		m.iface = detected
		log.Printf("ebpf: auto-detected interface %q", m.iface)
	}

	// Raise RLIMIT_MEMLOCK to allow eBPF map allocation.
	if err := allowUnlimitedLocked(); err != nil {
		log.Printf("ebpf: warning: could not raise RLIMIT_MEMLOCK: %v (may fail on older kernels)", err)
	}

	// Load the compiled eBPF objects (programs + maps) from embedded bytecode.
	objs := &captureObjects{}
	if err := loadCaptureObjects(objs, nil); err != nil {
		return fmt.Errorf("ebpf: load objects: %w", err)
	}
	m.objs = objs

	// Populate management ports map.
	one := uint8(1)
	for _, port := range m.mgmtPorts {
		if err := objs.MgmtPortsMap.Put(port, one); err != nil {
			objs.Close()
			return fmt.Errorf("ebpf: populate mgmt_ports_map port %d: %w", port, err)
		}
	}
	log.Printf("ebpf: populated mgmt_ports_map with %d ports", len(m.mgmtPorts))

	// Optionally populate management allow IPs map.
	if m.allowFile != "" {
		if err := m.loadAllowFile(objs, m.allowFile); err != nil {
			log.Printf("ebpf: warning: failed to load mgmt allow file %q: %v", m.allowFile, err)
			// Non-fatal: continue without the IP allowlist.
		}
	}

	// Resolve the interface index.
	ifaceIndex, err := InterfaceIndex(m.iface)
	if err != nil {
		objs.Close()
		return fmt.Errorf("ebpf: interface index: %w", err)
	}

	// Attach the XDP program. Try native mode first; fall back to SKB (generic) mode.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCapture,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode, // SKB mode works without hardware/driver support
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("ebpf: attach XDP to %q: %w", m.iface, err)
	}
	m.xdpLink = xdpLink

	// Open perf reader for the events map.
	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*64)
	if err != nil {
		xdpLink.Close()
		objs.Close()
		return fmt.Errorf("ebpf: open perf reader: %w", err)
	}
	m.eventsReader = reader

	m.startedAt = time.Now()
	m.active.Store(true)

	// Start background goroutines.
	go m.startEventReader(m.EventCh)
	go m.startStatsLoop()

	log.Printf("ebpf: XDP program attached to %q in %s mode", m.iface, m.mode)
	return nil
}

// Stop detaches the XDP program, closes all maps and the perf reader, and
// waits for background goroutines to finish.
//
// Safe to call on an inactive Manager (no-op).
func (m *Manager) Stop() error {
	if !m.active.Swap(false) {
		return nil
	}

	// Signal the stats loop to exit.
	close(m.stopCh)

	// Closing the perf reader causes the event reader goroutine to exit.
	if m.eventsReader != nil {
		if err := m.eventsReader.Close(); err != nil {
			log.Printf("ebpf: close perf reader: %v", err)
		}
	}

	// Detach the XDP program.
	if m.xdpLink != nil {
		if err := m.xdpLink.Close(); err != nil {
			log.Printf("ebpf: detach XDP: %v", err)
		}
	}

	// Close all eBPF objects (programs + maps).
	if m.objs != nil {
		m.objs.Close()
	}

	log.Printf("ebpf: XDP program detached from %q", m.iface)
	return nil
}

// Ban inserts or refreshes an entry in the eBPF ban_map for the given IP and
// port, expiring after duration.
//
// ip may be an IPv4 or IPv6 address string.
// port should be the decimal port string (e.g. "22").
//
// No-op if the Manager is inactive.
func (m *Manager) Ban(ipStr, portStr string, duration time.Duration) error {
	if !m.active.Load() || m.objs == nil {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("ebpf: Ban: invalid IP address %q", ipStr)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("ebpf: Ban: %w", err)
	}

	key, err := makeBanKey(ip, port)
	if err != nil {
		return fmt.Errorf("ebpf: Ban: %w", err)
	}

	// expires_at must use bpf_ktime_get_ns() epoch (nanoseconds since boot).
	// ktime_now ≈ kernel uptime in nanoseconds.
	uptime, err := kernelUptime()
	if err != nil {
		return fmt.Errorf("ebpf: Ban: get uptime: %w", err)
	}
	expiresNS := uint64(uptime.Nanoseconds()) + uint64(duration.Nanoseconds())

	val := banEntry{ExpiresAt: expiresNS}
	if err := m.objs.BanMap.Put(key, val); err != nil {
		return fmt.Errorf("ebpf: Ban: map update: %w", err)
	}
	return nil
}

// Unban removes the entry for ip:port from the eBPF ban_map.
// No-op if the Manager is inactive or the entry does not exist.
func (m *Manager) Unban(ipStr, portStr string) error {
	if !m.active.Load() || m.objs == nil {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("ebpf: Unban: invalid IP address %q", ipStr)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return fmt.Errorf("ebpf: Unban: %w", err)
	}

	key, err := makeBanKey(ip, port)
	if err != nil {
		return fmt.Errorf("ebpf: Unban: %w", err)
	}

	// Delete is idempotent — no error if the key does not exist.
	if err := m.objs.BanMap.Delete(key); err != nil && !isNotFound(err) {
		return fmt.Errorf("ebpf: Unban: map delete: %w", err)
	}
	return nil
}

// ReloadAllowFile re-reads the mgmt allow file and updates mgmt_allow_ips_map.
// Called by the SIGHUP handler. No-op if no allow file was configured.
func (m *Manager) ReloadAllowFile() error {
	if m.allowFile == "" || !m.active.Load() || m.objs == nil {
		return nil
	}
	// Clear the map first.
	if err := clearMap[ipKey, uint8](m.objs.MgmtAllowIpsMap); err != nil {
		return fmt.Errorf("ebpf: reload allow file: clear map: %w", err)
	}
	return m.loadAllowFile(m.objs, m.allowFile)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// makeBanKey constructs a banKey from a parsed net.IP (IPv4 or IPv6) and a
// uint16 port. The key matches the C struct ban_key layout: src_ip is the
// 16-byte (v4-mapped) address, dst_port is a big-endian uint16.
func makeBanKey(ip net.IP, port uint16) (banKey, error) {
	ip16 := ip.To16()
	if ip16 == nil {
		return banKey{}, fmt.Errorf("makeBanKey: not an IP address: %v", ip)
	}
	k := banKey{}
	copy(k.SrcIP[:], ip16)
	// Store port in network byte order to match the C XDP key construction.
	binary.BigEndian.PutUint16(k.DstPort[:], port)
	return k, nil
}

// loadAllowFile reads one IP address (v4 or v6) per line from path and populates the
// mgmt_allow_ips_map in objs.
func (m *Manager) loadAllowFile(objs *captureObjects, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	one := uint8(1)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := net.ParseIP(line).To16()
		if ip == nil {
			log.Printf("ebpf: allow file %q: skipping invalid IP %q", path, line)
			continue
		}
		var key ipKey
		copy(key.Addr[:], ip)
		if err := objs.MgmtAllowIpsMap.Put(key, one); err != nil {
			return fmt.Errorf("populate mgmt_allow_ips_map for %s: %w", line, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	log.Printf("ebpf: loaded %d IP(s) from allow file %q", count, path)
	return nil
}

// clearMap deletes all entries from an eBPF hash map by iterating keys then deleting.
// K is the map's key type and V its value type.
func clearMap[K, V any](m *ebpf.Map) error {
	var key K
	var val V
	iter := m.Iterate()
	var keys []K
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// isNotFound returns true for ebpf.ErrKeyNotExist.
func isNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}

// parsePort converts a decimal port string to uint16.
func parsePort(s string) (uint16, error) {
	var p uint16
	_, err := fmt.Sscanf(s, "%d", &p)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	return p, nil
}

// kernelUptime reads /proc/uptime and returns the system uptime.
func kernelUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	var seconds float64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%f", &seconds); err != nil {
		return 0, err
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
