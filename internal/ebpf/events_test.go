package ebpf

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
)

// buildRawRecord constructs a perf.Record with the 20-byte wire payload.
// srcIPInt is the IPv4 address as a big-endian uint32 (0x01020304 = 1.2.3.4);
// it is encoded as a v4-mapped address, as the XDP program does.
func buildRawRecord(srcIPInt uint32, dstPort uint16, dropped uint8, protocol uint8) perf.Record {
	b := make([]byte, rawEventSize)
	b[10], b[11] = 0xff, 0xff
	b[12] = byte(srcIPInt >> 24)
	b[13] = byte(srcIPInt >> 16)
	b[14] = byte(srcIPInt >> 8)
	b[15] = byte(srcIPInt)
	b[16] = byte(dstPort)
	b[17] = byte(dstPort >> 8)
	b[18] = dropped
	b[19] = protocol
	return perf.Record{RawSample: b}
}

func TestParseEventBasic(t *testing.T) {
	srcIPInt := uint32(0x01020304) // 1.2.3.4
	rec := buildRawRecord(srcIPInt, 80, 0, ProtoTCP)

	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	wantIP := net.IP{1, 2, 3, 4}
	if !ev.SrcIP.Equal(wantIP) {
		t.Errorf("SrcIP = %v, want %v", ev.SrcIP, wantIP)
	}
	if ev.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", ev.DstPort)
	}
	if ev.Dropped {
		t.Error("Dropped should be false")
	}
	if ev.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want \"tcp\"", ev.Protocol)
	}
	// Timestamp must be recent.
	if time.Since(ev.Time) > 5*time.Second {
		t.Errorf("Time is stale: %v", ev.Time)
	}
}

func TestParseEventDropped(t *testing.T) {
	rec := buildRawRecord(0x01020304, 443, 1, ProtoTCP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if !ev.Dropped {
		t.Error("Dropped should be true when byte 6 = 1")
	}
}

func TestParseEventDroppedNonZero(t *testing.T) {
	// Any non-zero value for the dropped byte should be treated as dropped.
	rec := buildRawRecord(0x01020304, 22, 0xFF, ProtoTCP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if !ev.Dropped {
		t.Error("Dropped should be true for dropped byte = 0xFF")
	}
}

func TestParseEventTooShort(t *testing.T) {
	// Records shorter than 20 bytes must return an error.
	for i := 0; i < rawEventSize; i++ {
		rec := perf.Record{RawSample: make([]byte, i)}
		_, err := parseEvent(rec)
		if err == nil {
			t.Errorf("parseEvent with %d bytes: expected error, got nil", i)
		}
	}
}

func TestParseEventExactSize(t *testing.T) {
	rec := buildRawRecord(0xC0A80101, 8080, 0, ProtoTCP) // 192.168.1.1
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.DstPort != 8080 {
		t.Errorf("DstPort = %d, want 8080", ev.DstPort)
	}
}

func TestParseEventExtraBytes(t *testing.T) {
	// Extra trailing bytes beyond 20 should be silently ignored.
	b := make([]byte, rawEventSize+4)
	b[16] = 0x50 // port 80 LE
	rec := perf.Record{RawSample: b}
	_, err := parseEvent(rec)
	if err != nil {
		t.Errorf("parseEvent with extra bytes: unexpected error: %v", err)
	}
}

func TestParseEventIPConversion(t *testing.T) {
	// Verify IP conversion for a well-known address: 8.8.8.8
	// In LE uint32: 0x08080808 (symmetric, same in both orderings)
	rec := buildRawRecord(0x08080808, 53, 0, ProtoUDP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	want := net.IP{8, 8, 8, 8}
	if !ev.SrcIP.Equal(want) {
		t.Errorf("SrcIP = %v, want %v", ev.SrcIP, want)
	}
}

func TestParseEventHighPort(t *testing.T) {
	// Port 65535 = 0xFFFF, LE bytes: FF FF
	rec := buildRawRecord(0x7F000001, 65535, 0, ProtoTCP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.DstPort != 65535 {
		t.Errorf("DstPort = %d, want 65535", ev.DstPort)
	}
}

func TestParseEventProtocolUDP(t *testing.T) {
	rec := buildRawRecord(0x01020304, 53, 0, ProtoUDP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.Protocol != "udp" {
		t.Errorf("Protocol = %q, want \"udp\"", ev.Protocol)
	}
}

func TestParseEventProtocolICMP(t *testing.T) {
	rec := buildRawRecord(0x01020304, 0, 0, ProtoICMP)
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.Protocol != "icmp" {
		t.Errorf("Protocol = %q, want \"icmp\"", ev.Protocol)
	}
	if ev.DstPort != 0 {
		t.Errorf("DstPort = %d, want 0 for ICMP", ev.DstPort)
	}
}

func TestParseEventProtocolUnknown(t *testing.T) {
	rec := buildRawRecord(0x01020304, 80, 0, 47) // GRE = 47
	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if ev.Protocol != "proto-47" {
		t.Errorf("Protocol = %q, want \"proto-47\"", ev.Protocol)
	}
}

func TestParseEventIPv6(t *testing.T) {
	b := make([]byte, rawEventSize)
	copy(b, net.ParseIP("2001:db8::1").To16())
	b[16], b[17] = 22, 0
	b[19] = ProtoTCP
	ev, err := parseEvent(perf.Record{RawSample: b})
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if got := ev.SrcIP.String(); got != "2001:db8::1" {
		t.Errorf("SrcIP = %s, want 2001:db8::1", got)
	}
}

func TestProtoICMPv6(t *testing.T) {
	if protoString(ProtoICMPv6) != "icmp" {
		t.Error("ICMPv6 should map to icmp")
	}
}
