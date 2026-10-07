package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

// ── synthetic packets ────────────────────────────────────────────────────────

func ethHeader(etherType uint16) []byte {
	h := make([]byte, 14)
	copy(h[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})
	copy(h[6:12], []byte{0x02, 0, 0, 0, 0, 0x02})
	binary.BigEndian.PutUint16(h[12:], etherType)
	return h
}

func pad(b []byte) []byte {
	for len(b) < 64 {
		b = append(b, 0)
	}
	return b
}

func ipv4Packet(src, dst string, proto byte, l4 []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8], ip[9] = 64, proto
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())
	return pad(append(append(ethHeader(0x0800), ip...), l4...))
}

func ipv6Packet(src, dst string, next byte, l4 []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
	ip[6], ip[7] = next, 64
	copy(ip[8:24], net.ParseIP(src).To16())
	copy(ip[24:40], net.ParseIP(dst).To16())
	return pad(append(append(ethHeader(0x86dd), ip...), l4...))
}

func udpHeader(dport uint16) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], 5353)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], 8)
	return u
}

func tcpSYN(dport uint16) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], 40000)
	binary.BigEndian.PutUint16(t[2:], dport)
	t[12] = 5 << 4
	t[13] = 0x02 // SYN
	return t
}

func icmpEcho() []byte { return []byte{8, 0, 0, 0, 0, 1, 0, 1} }

// passed sums the per-CPU "passed" telemetry counter.
func passed(t *testing.T, m *cebpf.Map) uint64 {
	t.Helper()
	var vals []uint64
	if err := m.Lookup(uint32(0), &vals); err != nil {
		t.Fatal(err)
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	return sum
}

// TestXDPIgnoresMulticastAndBroadcast runs real packets through the loaded
// program (BPF_PROG_TEST_RUN) and checks which ones are counted/reported.
// Skipped when the process cannot load BPF programs.
func TestXDPIgnoresMulticastAndBroadcast(t *testing.T) {
	_ = allowUnlimitedLocked()
	var objs captureObjects
	if err := loadCaptureObjects(&objs, nil); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("insufficient privileges to load BPF: %v", err)
		}
		t.Skipf("cannot load BPF in this environment: %v", err)
	}
	defer objs.Close()

	cases := []struct {
		name    string
		pkt     []byte
		counted bool // should the program treat it as ordinary (counted) traffic?
	}{
		{"unicast UDP", ipv4Packet("203.0.113.5", "192.0.2.10", 17, udpHeader(5353)), true},
		{"unicast TCP SYN", ipv4Packet("203.0.113.5", "192.0.2.10", 6, tcpSYN(8081)), true},
		{"unicast ICMP", ipv4Packet("203.0.113.5", "192.0.2.10", 1, icmpEcho()), true},
		{"unicast IPv6 UDP", ipv6Packet("2001:db8::5", "2001:db8::10", 17, udpHeader(5353)), true},
		{"mDNS IPv4 multicast", ipv4Packet("192.168.1.20", "224.0.0.251", 17, udpHeader(5353)), false},
		{"SSDP multicast", ipv4Packet("192.168.1.20", "239.255.255.250", 17, udpHeader(1900)), false},
		{"limited broadcast (DHCP)", ipv4Packet("0.0.0.0", "255.255.255.255", 17, udpHeader(67)), false},
		{"multicast ICMP", ipv4Packet("192.168.1.20", "224.0.0.1", 1, icmpEcho()), false},
		{"mDNS IPv6 multicast", ipv6Packet("fe80::1", "ff02::fb", 17, udpHeader(5353)), false},
		{"IPv6 multicast TCP", ipv6Packet("2001:db8::5", "ff0e::1", 6, tcpSYN(80)), false},
	}
	for _, c := range cases {
		before := passed(t, objs.TelemetryMap)
		verdict, _, err := objs.XdpCapture.Test(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if verdict != 2 { // XDP_PASS: the program must never drop these
			t.Errorf("%s: verdict %d, want XDP_PASS(2)", c.name, verdict)
		}
		got := passed(t, objs.TelemetryMap) - before
		if c.counted && got != 1 {
			t.Errorf("%s: passed counter +%d, want +1", c.name, got)
		}
		if !c.counted && got != 0 {
			t.Errorf("%s: multicast/broadcast must be ignored, but counter +%d", c.name, got)
		}
	}
}
