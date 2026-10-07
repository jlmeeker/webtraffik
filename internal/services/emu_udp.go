package services

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// UDP responders. Datagram services are trivially spoofable, so these follow
// two hard rules:
//
//  1. A reply is never larger than the request that triggered it (enforced in
//     serveUDP, not left to the individual handlers), so the sensor can not
//     amplify traffic.
//  2. Replies are rate limited per source address.
//
// Known amplification vectors (memcached stats, NTP monlist/readvar, SSDP
// M-SEARCH) are tagged "amplification-probe" and answered with nothing or
// with something minimal.

const tagAmplification = "amplification-probe"

// udpHandler inspects one datagram and returns the reply to send (nil for
// none) plus what to record. A nil res.Data records the datagram itself.
type udpHandler func(pkt []byte) (reply []byte, res Result)

// udpHandlers are the UDP ports with a responder; the rest are capture-only.
var udpHandlers = map[int]udpHandler{
	123:   ntpUDP,
	1900:  ssdpUDP,
	5060:  sipUDP,
	11211: memcachedUDP,
}

const (
	udpReplyBurst  = 5                // replies per source per window
	udpReplyWindow = 10 * time.Second // rate-limit window
	udpLimiterMax  = 8192             // tracked sources before the table is reset
)

// replyLimiter is a per-source fixed-window limiter. Owned by the single
// goroutine that reads the socket, so it needs no lock.
type replyLimiter struct {
	m map[string]*limitSlot
}

type limitSlot struct {
	start time.Time
	n     int
}

func (l *replyLimiter) allow(ip string, now time.Time) bool {
	if l.m == nil || len(l.m) >= udpLimiterMax {
		l.m = make(map[string]*limitSlot)
	}
	s := l.m[ip]
	if s == nil || now.Sub(s.start) > udpReplyWindow {
		l.m[ip] = &limitSlot{start: now, n: 1}
		return true
	}
	s.n++
	return s.n <= udpReplyBurst
}

// replyAllowed is the anti-amplification rule: a reply must exist and be no
// larger than the request.
func replyAllowed(reply, req []byte) bool { return len(reply) > 0 && len(reply) <= len(req) }

// safeUDP runs h, converting a panic into "no reply" so one hostile datagram
// can not kill the read loop.
func safeUDP(h udpHandler, pkt []byte) (reply []byte, res Result) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("udp handler panic", "panic", r)
			reply, res = nil, Result{Detail: "handler error"}
		}
	}()
	return h(pkt)
}

// serveUDP reads datagrams from pc until it is closed, recording each one and
// answering through h when it is non-nil.
func (e *Env) serveUDP(ctx context.Context, pc net.PacketConn, port int, h udpHandler) {
	portStr := strconv.Itoa(port)
	var lim replyLimiter
	buf := make([]byte, 2048)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("udp read", "port", port, "err", err)
			time.Sleep(time.Second)
			continue
		}
		srcIP := extractConnIP(src)
		pkt := buf[:n]
		cp := Capture{SrcIP: srcIP, DstPort: portStr, Protocol: "udp"}
		if h == nil {
			cp.Data = append([]byte(nil), clip(pkt, 512)...)
			e.Capture(cp)
			continue
		}
		reply, res := safeUDP(h, pkt)
		cp.Data = append([]byte(nil), clip(res.Data, 512)...)
		if res.Data == nil {
			cp.Data = append([]byte(nil), clip(pkt, 512)...)
		}
		cp.Detail, cp.Tags, cp.Meta = res.Detail, res.Tags, res.Meta
		if replyAllowed(reply, pkt) && lim.allow(srcIP, time.Now()) {
			pc.SetWriteDeadline(time.Now().Add(time.Second))
			pc.WriteTo(reply, src)
		}
		e.Capture(cp)
	}
}

// ── memcached ─────────────────────────────────────────────────────────────────

// memcachedUDP parses the 8-byte UDP frame header (request id, sequence, total
// datagrams, reserved) and the text command that follows. stats/get are the
// classic amplification vectors; the reply is a bare "END".
func memcachedUDP(pkt []byte) ([]byte, Result) {
	if len(pkt) < 8 {
		return nil, Result{Detail: "memcached: short datagram (no frame header)"}
	}
	hdr := pkt[:8]
	line := pkt[8:]
	if i := bytes.Index(line, []byte("\r\n")); i >= 0 {
		line = line[:i]
	}
	line = clip(line, 256)
	cmd, _, _ := strings.Cut(strings.TrimSpace(string(line)), " ")
	cmd = strings.ToLower(cleanStr(cmd, 24))
	meta := map[string]string{
		"memcached_request_id": fmt.Sprintf("%04x", binary.BigEndian.Uint16(hdr)),
	}
	if cmd != "" {
		meta["memcached_cmd"] = cmd
	}
	res := Result{Detail: "memcached: " + cleanStr(string(line), 80), Meta: meta}
	if cmd == "" {
		res.Detail = "memcached: frame without command"
	}
	switch cmd {
	case "stats", "get", "gets", "gat", "gats":
		res.Tags = []string{tagAmplification}
	}
	frame := func(body string) []byte {
		return append([]byte{hdr[0], hdr[1], 0, 0, 0, 1, 0, 0}, body...)
	}
	switch cmd {
	case "stats", "get", "gets", "gat", "gats":
		return fit(pkt, frame("END\r\n"), frame("ERROR\r\n")), res
	case "version":
		return fit(pkt, frame("VERSION 1.6.21\r\n"), frame("ERROR\r\n")), res
	default:
		return fit(pkt, frame("ERROR\r\n")), res
	}
}

// ── NTP ───────────────────────────────────────────────────────────────────────

// ntpUDP classifies NTP datagrams and never answers any of them. NTP runs over
// spoofable UDP, so even a reply the size of the request would reflect traffic
// at a forged source address. Mode 7 (monlist, ntpdc) and mode 6 (ntpq
// readvar/readstat) are additionally tagged as amplification vectors.
func ntpUDP(pkt []byte) ([]byte, Result) {
	if len(pkt) == 0 {
		return nil, Result{Detail: "ntp: empty datagram"}
	}
	b0 := pkt[0]
	vn, mode := (b0>>3)&7, b0&7
	meta := map[string]string{"ntp_mode": strconv.Itoa(int(mode)), "ntp_version": strconv.Itoa(int(vn))}
	res := Result{Meta: meta}
	switch mode {
	case 7:
		res.Detail = "ntp: mode-7 private request"
		if len(pkt) >= 4 {
			meta["ntp_reqcode"] = strconv.Itoa(int(pkt[3]))
			if pkt[3] == 42 || pkt[3] == 20 {
				res.Detail = "ntp: mode-7 monlist request"
			}
		}
		res.Tags = []string{tagAmplification}
		return nil, res
	case 6:
		res.Detail = "ntp: mode-6 control request"
		if len(pkt) >= 2 {
			meta["ntp_opcode"] = strconv.Itoa(int(pkt[1] & 0x1f))
		}
		res.Tags = []string{tagAmplification}
		return nil, res
	case 3:
		res.Detail = fmt.Sprintf("ntp: client request v%d", vn)
		if len(pkt) < 48 {
			res.Detail += " (short)"
		}
		return nil, res
	}
	res.Detail = fmt.Sprintf("ntp: mode %d packet", mode)
	return nil, res
}

// ── SSDP ──────────────────────────────────────────────────────────────────────

// ssdpUDP records unicast M-SEARCH probes. A real UPnP answer (LOCATION, USN…)
// is larger than the request, so none is sent.
func ssdpUDP(pkt []byte) ([]byte, Result) {
	text := string(clip(pkt, 1024))
	lines := strings.Split(text, "\n")
	first := cleanStr(strings.TrimSpace(lines[0]), 64)
	method, _, _ := strings.Cut(first, " ")
	meta := map[string]string{}
	if method != "" {
		meta["ssdp_method"] = strings.ToUpper(method)
	}
	for i, l := range lines {
		if i == 0 || i > 32 {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "st", "nt":
			meta["ssdp_st"] = cleanStr(strings.TrimSpace(v), 128)
		case "user-agent", "server":
			meta["user_agent"] = cleanStr(strings.TrimSpace(v), 200)
		}
	}
	res := Result{Detail: "ssdp: " + first, Meta: meta}
	var tags []string
	if strings.EqualFold(method, "M-SEARCH") {
		tags = append(tags, tagAmplification)
	}
	res.Tags = mergeTags(tags, Classify(text, meta["user_agent"]))
	return nil, res
}
