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

// UDP listeners. The source address of a datagram can be forged, so any reply
// — even one no larger than the request — would let an attacker bounce traffic
// off this host at a victim. UDP is therefore capture-only: nothing is ever
// written to a UDP socket. The handlers below only parse what arrived so the
// capture carries useful detail and tags.
//
// Known amplification vectors (memcached stats, NTP monlist/readvar, SSDP
// M-SEARCH) are tagged "amplification-probe".

const tagAmplification = "amplification-probe"

// udpHandler inspects one datagram and returns what to record. A nil
// res.Data records the datagram itself.
type udpHandler func(pkt []byte) Result

// udpHandlers are the UDP ports whose datagrams are parsed; the rest are
// recorded raw. None of them ever answers.
var udpHandlers = map[int]udpHandler{
	123:   ntpUDP,
	1900:  ssdpUDP,
	5060:  sipUDP,
	11211: memcachedUDP,
}

// safeUDP runs h, converting a panic into a bare record so one hostile
// datagram can not kill the read loop.
func safeUDP(h udpHandler, pkt []byte) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("udp handler panic", "panic", r)
			res = Result{Detail: "handler error"}
		}
	}()
	return h(pkt)
}

// serveUDP reads datagrams from pc until it is closed and records each one
// (parsed by h when non-nil). It never writes to pc.
func (e *Env) serveUDP(ctx context.Context, pc net.PacketConn, port int, h udpHandler) {
	portStr := strconv.Itoa(port)
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
		res := safeUDP(h, pkt)
		cp.Data = append([]byte(nil), clip(res.Data, 512)...)
		if res.Data == nil {
			cp.Data = append([]byte(nil), clip(pkt, 512)...)
		}
		cp.Detail, cp.Tags, cp.Meta = res.Detail, res.Tags, res.Meta
		e.Capture(cp)
	}
}

// ── memcached ─────────────────────────────────────────────────────────────────

// memcachedUDP parses the 8-byte UDP frame header (request id, sequence, total
// datagrams, reserved) and the text command that follows. stats/get are the
// classic amplification vectors.
func memcachedUDP(pkt []byte) Result {
	if len(pkt) < 8 {
		return Result{Detail: "memcached: short datagram (no frame header)"}
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
	return res
}

// ── NTP ───────────────────────────────────────────────────────────────────────

// ntpUDP classifies NTP datagrams. Mode 7 (monlist, ntpdc) and mode 6 (ntpq
// readvar/readstat) are additionally tagged as amplification vectors.
func ntpUDP(pkt []byte) Result {
	if len(pkt) == 0 {
		return Result{Detail: "ntp: empty datagram"}
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
		return res
	case 6:
		res.Detail = "ntp: mode-6 control request"
		if len(pkt) >= 2 {
			meta["ntp_opcode"] = strconv.Itoa(int(pkt[1] & 0x1f))
		}
		res.Tags = []string{tagAmplification}
		return res
	case 3:
		res.Detail = fmt.Sprintf("ntp: client request v%d", vn)
		if len(pkt) < 48 {
			res.Detail += " (short)"
		}
		return res
	}
	res.Detail = fmt.Sprintf("ntp: mode %d packet", mode)
	return res
}

// ── SSDP ──────────────────────────────────────────────────────────────────────

// ssdpUDP records unicast M-SEARCH probes.
func ssdpUDP(pkt []byte) Result {
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
	return res
}
