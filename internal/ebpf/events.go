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
// It mirrors the C `struct event` exactly (8 bytes, host byte order after
// bpf_perf_event_output which copies raw bytes).
type RawEvent struct {
	SrcIP    uint32 // IPv4 source address (host byte order)
	DstPort  uint16 // destination port (host byte order)
	Dropped  uint8  // 1 = XDP_DROP (banned), 0 = XDP_PASS
	Protocol uint8  // IPPROTO_TCP (6), IPPROTO_UDP (17), or IPPROTO_ICMP (1)
}

// IP protocol numbers used by the XDP program.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// protoString converts an IP protocol number to a lowercase string.
func protoString(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
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
// The record data must be exactly 8 bytes (sizeof struct event in C).
func parseEvent(rec perf.Record) (Event, error) {
	if len(rec.RawSample) < 8 {
		return Event{}, fmt.Errorf("ebpf: short event record: %d bytes", len(rec.RawSample))
	}
	b := rec.RawSample
	// Little-endian layout (x86/arm host byte order):
	//   bytes 0-3: src_ip   (uint32 LE)
	//   bytes 4-5: dst_port (uint16 LE)
	//   byte  6:   dropped  (uint8)
	//   byte  7:   protocol (uint8: 6=TCP, 17=UDP, 1=ICMP)
	srcIPInt := binary.LittleEndian.Uint32(b[0:4])
	dstPort := binary.LittleEndian.Uint16(b[4:6])
	dropped := b[6] != 0
	proto := b[7]

	// Convert uint32 to net.IP (big-endian byte slice).
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, srcIPInt)

	return Event{
		SrcIP:    ip,
		DstPort:  dstPort,
		Dropped:  dropped,
		Protocol: protoString(proto),
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
