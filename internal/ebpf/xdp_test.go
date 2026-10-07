package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
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

func udpHeader(dport uint16) []byte { return udpPorts(5353, dport) }

func udpPorts(sport, dport uint16) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
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

func icmpEcho() []byte { return icmpType(8) }

func icmpType(t byte) []byte { return []byte{t, 0, 0, 0, 0, 1, 0, 1} }

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

// TestXDPSuppressesReplyEvents checks, with real packets, which ones produce an
// event on the perf buffer: replies to this host's own outbound traffic must
// not, genuine probes must, and every packet must still be XDP_PASSed and
// counted. Banned traffic must still be dropped.
func TestXDPSuppressesReplyEvents(t *testing.T) {
	_ = allowUnlimitedLocked()
	var objs captureObjects
	if err := loadCaptureObjects(&objs, nil); err != nil {
		t.Skipf("cannot load BPF in this environment: %v", err)
	}
	defer objs.Close()
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*8)
	if err != nil {
		t.Skipf("cannot open perf reader: %v", err)
	}
	defer rd.Close()

	const src, dst = "203.0.113.5", "192.0.2.10"
	const s6, d6 = "2001:db8::5", "2001:db8::10"
	cases := []struct {
		name  string
		pkt   []byte
		event bool
	}{
		// ICMPv4 replies: no event.
		{"icmp echo reply", ipv4Packet(src, dst, 1, icmpType(0)), false},
		{"icmp dest unreachable", ipv4Packet(src, dst, 1, icmpType(3)), false},
		{"icmp source quench", ipv4Packet(src, dst, 1, icmpType(4)), false},
		{"icmp redirect", ipv4Packet(src, dst, 1, icmpType(5)), false},
		{"icmp time exceeded", ipv4Packet(src, dst, 1, icmpType(11)), false},
		{"icmp param problem", ipv4Packet(src, dst, 1, icmpType(12)), false},
		{"icmp timestamp reply", ipv4Packet(src, dst, 1, icmpType(14)), false},
		{"icmp info reply", ipv4Packet(src, dst, 1, icmpType(16)), false},
		{"icmp mask reply", ipv4Packet(src, dst, 1, icmpType(18)), false},
		// ICMPv4 probes: event.
		{"icmp echo request", ipv4Packet(src, dst, 1, icmpType(8)), true},
		{"icmp timestamp request", ipv4Packet(src, dst, 1, icmpType(13)), true},
		{"icmp info request", ipv4Packet(src, dst, 1, icmpType(15)), true},
		{"icmp mask request", ipv4Packet(src, dst, 1, icmpType(17)), true},
		// ICMPv6.
		{"icmp6 echo request", ipv6Packet(s6, d6, 58, icmpType(128)), true},
		{"icmp6 echo reply", ipv6Packet(s6, d6, 58, icmpType(129)), false},
		{"icmp6 dest unreachable", ipv6Packet(s6, d6, 58, icmpType(1)), false},
		{"icmp6 packet too big", ipv6Packet(s6, d6, 58, icmpType(2)), false},
		{"icmp6 time exceeded", ipv6Packet(s6, d6, 58, icmpType(3)), false},
		{"icmp6 param problem", ipv6Packet(s6, d6, 58, icmpType(4)), false},
		{"icmp6 neighbor advert", ipv6Packet(s6, d6, 58, icmpType(136)), false},
		{"icmp6 redirect", ipv6Packet(s6, d6, 58, icmpType(137)), false},
		// UDP replies: server source port -> ephemeral destination port.
		{"dns reply", ipv4Packet(src, dst, 17, udpPorts(53, 40000)), false},
		{"ntp reply", ipv4Packet(src, dst, 17, udpPorts(123, 32768)), false},
		{"mdns reply to ephemeral", ipv4Packet(src, dst, 17, udpPorts(5353, 50000)), false},
		{"stun reply", ipv4Packet(src, dst, 17, udpPorts(3478, 50000)), false},
		{"sip reply", ipv4Packet(src, dst, 17, udpPorts(5060, 50000)), false},
		{"ipv6 dns reply", ipv6Packet(s6, d6, 17, udpPorts(53, 40000)), false},
		// UDP probes: event.
		{"udp to low port", ipv4Packet(src, dst, 17, udpPorts(40000, 161)), true},
		{"udp high src to high dst", ipv4Packet(src, dst, 17, udpPorts(40000, 50000)), true},
		{"udp low src to low dst", ipv4Packet(src, dst, 17, udpPorts(53, 1023)), true},
		{"udp low src to non-ephemeral dst", ipv4Packet(src, dst, 17, udpPorts(53, 32767)), true},
		{"udp 5353 to low port", ipv4Packet(src, dst, 17, udpPorts(5353, 5353)), true},
		{"udp 5060 to non-ephemeral dst", ipv4Packet(src, dst, 17, udpPorts(5060, 5060)), true},
		{"ipv6 udp to low port", ipv6Packet(s6, d6, 17, udpPorts(40000, 161)), true},
		// TCP SYN: event.
		{"tcp syn", ipv4Packet(src, dst, 6, tcpSYN(8081)), true},
		{"ipv6 tcp syn", ipv6Packet(s6, d6, 6, tcpSYN(8081)), true},
	}
	for _, c := range cases {
		before := passed(t, objs.TelemetryMap)
		verdict, _, err := objs.XdpCapture.Test(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if verdict != 2 {
			t.Errorf("%s: verdict %d, want XDP_PASS(2)", c.name, verdict)
		}
		if got := passed(t, objs.TelemetryMap) - before; got != 1 {
			t.Errorf("%s: passed counter +%d, want +1 (replies are still counted)", c.name, got)
		}
		if ev := readEvent(t, rd); ev != c.event {
			t.Errorf("%s: event emitted = %v, want %v", c.name, ev, c.event)
		}
	}

	// Banned traffic is still dropped, and reported.
	k, err := makeBanKey(net.ParseIP(src), 161)
	if err != nil {
		t.Fatal(err)
	}
	if err := objs.BanMap.Put(k, banEntry{ExpiresAt: 1 << 62}); err != nil {
		t.Fatal(err)
	}
	verdict, _, err := objs.XdpCapture.Test(ipv4Packet(src, dst, 17, udpPorts(40000, 161)))
	if err != nil {
		t.Fatal(err)
	}
	if verdict != 1 { // XDP_DROP
		t.Errorf("banned probe: verdict %d, want XDP_DROP(1)", verdict)
	}
	if !readEvent(t, rd) {
		t.Errorf("banned probe: drop event not emitted")
	}
	// Ban enforcement is unchanged for a reply-shaped packet to a banned
	// port... but the destination there is below 32768, so it is no reply.
	verdict, _, err = objs.XdpCapture.Test(ipv4Packet(src, dst, 17, udpPorts(53, 161)))
	if err != nil {
		t.Fatal(err)
	}
	if verdict != 1 {
		t.Errorf("banned low-src probe: verdict %d, want XDP_DROP(1)", verdict)
	}
	_ = readEvent(t, rd)
	// A ban on an ephemeral port still drops reply-shaped packets, silently.
	k, _ = makeBanKey(net.ParseIP(src), 40000)
	if err := objs.BanMap.Put(k, banEntry{ExpiresAt: 1 << 62}); err != nil {
		t.Fatal(err)
	}
	verdict, _, err = objs.XdpCapture.Test(ipv4Packet(src, dst, 17, udpPorts(53, 40000)))
	if err != nil {
		t.Fatal(err)
	}
	if verdict != 1 {
		t.Errorf("banned reply-shaped packet: verdict %d, want XDP_DROP(1)", verdict)
	}
	if readEvent(t, rd) {
		t.Errorf("banned reply-shaped packet: unexpected event")
	}
}

// readEvent reports whether a perf event is pending, consuming it.
func readEvent(t *testing.T, rd *perf.Reader) bool {
	t.Helper()
	rd.SetDeadline(time.Now().Add(-time.Second)) // already expired: non-blocking
	_, err := rd.Read()
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	t.Fatalf("perf read: %v", err)
	return false
}
