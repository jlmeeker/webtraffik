package ebpf

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
)

// buildRawRecord constructs a perf.Record with the given 8-byte wire payload.
// protocol is the IP protocol number (6=TCP, 17=UDP, 1=ICMP).
func buildRawRecord(srcIPInt uint32, dstPort uint16, dropped uint8, protocol uint8) perf.Record {
	b := make([]byte, 8)
	// Little-endian layout matching the C struct event:
	//   bytes 0-3: src_ip   (uint32 LE)
	//   bytes 4-5: dst_port (uint16 LE)
	//   byte  6:   dropped
	//   byte  7:   protocol
	b[0] = byte(srcIPInt)
	b[1] = byte(srcIPInt >> 8)
	b[2] = byte(srcIPInt >> 16)
	b[3] = byte(srcIPInt >> 24)
	b[4] = byte(dstPort)
	b[5] = byte(dstPort >> 8)
	b[6] = dropped
	b[7] = protocol
	return perf.Record{RawSample: b}
}

func TestParseEventBasic(t *testing.T) {
	// 1.2.3.4 in little-endian uint32 = 0x04030201
	srcIPInt := uint32(0x04030201) // LE: bytes are 01 02 03 04
	rec := buildRawRecord(srcIPInt, 80, 0, ProtoTCP)

	ev, err := parseEvent(rec)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	wantIP := net.IP{4, 3, 2, 1} // BigEndian decode of 0x04030201
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
	// Records shorter than 8 bytes must return an error.
	for i := 0; i < 8; i++ {
		rec := perf.Record{RawSample: make([]byte, i)}
		_, err := parseEvent(rec)
		if err == nil {
			t.Errorf("parseEvent with %d bytes: expected error, got nil", i)
		}
	}
}

func TestParseEventExactlyEightBytes(t *testing.T) {
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
	// Extra trailing bytes beyond 8 should be silently ignored.
	b := make([]byte, 12)
	b[4] = 0x50 // port 80 LE
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
