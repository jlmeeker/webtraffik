package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/perf"
)

// RawEvent is the wire format emitted by the XDP program into the perf buffer.
// It mirrors the C `struct event` exactly (20 bytes; the port is in host
// byte order, which bpf_perf_event_output copies raw).
type RawEvent struct {
	SrcIP    [16]byte // v4-mapped or native IPv6 source address, network order
	DstPort  uint16   // destination port (host byte order)
	Dropped  uint8    // 1 = XDP_DROP (banned), 0 = XDP_PASS
	Protocol uint8    // IPPROTO_TCP (6), IPPROTO_UDP (17), ICMP (1) or ICMPv6 (58)
}

const rawEventSize = 20

// IP protocol numbers used by the XDP program.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// protoString converts an IP protocol number to a lowercase string.
func protoString(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP, ProtoICMPv6:
		return "icmp"
	default:
		return fmt.Sprintf("proto-%d", p)
	}
}

// Event is the Go-idiomatic parsed representation of a RawEvent.
type Event struct {
	SrcIP    net.IP
	DstPort  uint16
	Dropped  bool
	Protocol string // "tcp", "udp", or "icmp"
	Time     time.Time
}

// parseEvent converts a raw perf.Record into an Event.
// The record data must be at least 20 bytes (sizeof struct event in C).
func parseEvent(rec perf.Record) (Event, error) {
	b := rec.RawSample
	if len(b) < rawEventSize {
		return Event{}, fmt.Errorf("ebpf: short event record: %d bytes", len(b))
	}
	//   bytes 0-15:  src_ip   (16 bytes, network order, v4-mapped for IPv4)
	//   bytes 16-17: dst_port (uint16 host/little-endian)
	//   byte  18:    dropped
	//   byte  19:    protocol
	ip := make(net.IP, 16)
	copy(ip, b[0:16])
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return Event{
		SrcIP:    ip,
		DstPort:  binary.LittleEndian.Uint16(b[16:18]),
		Dropped:  b[18] != 0,
		Protocol: protoString(b[19]),
		Time:     time.Now(),
	}, nil
}

// startEventReader opens a perf.Reader on the events map and pumps parsed
// Events into ch. It exits when the reader is closed (Manager.Stop() calls
// eventsReader.Close() which causes Read() to return an error).
//
// Errors on individual records (malformed) are logged and skipped rather than
// terminating the reader loop.
func (m *Manager) startEventReader(ch chan<- Event) {
	defer close(ch)
	for {
		rec, err := m.eventsReader.Read()
		if err != nil {
			// perf.ErrClosed is the expected shutdown signal.
			if err.Error() != "perf reader closed" {
				log.Printf("ebpf: perf reader error: %v", err)
			}
			return
		}

		if rec.LostSamples > 0 {
			log.Printf("ebpf: lost %d perf samples (ring buffer overflow)", rec.LostSamples)
		}

		ev, err := parseEvent(rec)
		if err != nil {
			log.Printf("ebpf: %v", err)
			continue
		}

		// Non-blocking send: if the consumer is lagging, drop the event rather
		// than stalling the perf reader goroutine.
		select {
		case ch <- ev:
		default:
			log.Printf("ebpf: event channel full, dropping event from %s:%d", ev.SrcIP, ev.DstPort)
		}
	}
}
