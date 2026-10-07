package services

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// ── RDP ───────────────────────────────────────────────────────────────────────

const (
	rdpMaxTPKT = 4096
	rdpCookie  = "Cookie: mstshash="
)

type rdpRequest struct {
	User      string // from "Cookie: mstshash=<user>"
	Cookie    bool   // any "Cookie:" line was present
	HasNeg    bool   // an RDP_NEG_REQ was present
	Protocols uint32 // requestedProtocols from RDP_NEG_REQ
	SrcRef    [2]byte
}

func rdpProtocolNames(p uint32) string {
	if p == 0 {
		return "standard"
	}
	var n []string
	for _, f := range []struct {
		bit  uint32
		name string
	}{{1, "tls"}, {2, "credssp"}, {4, "rdstls"}, {8, "credssp-ex"}} {
		if p&f.bit != 0 {
			n = append(n, f.name)
		}
	}
	if p&^uint32(0xf) != 0 {
		n = append(n, "unknown")
	}
	return strings.Join(n, ",")
}

// parseRDPConnReq decodes a complete TPKT-framed X.224 Connection Request.
func parseRDPConnReq(pkt []byte) (r rdpRequest, err error) {
	if len(pkt) < 11 || pkt[0] != 3 || pkt[1] != 0 {
		return r, errors.New("not a TPKT")
	}
	if int(binary.BigEndian.Uint16(pkt[2:])) < 11 {
		return r, errors.New("bad TPKT length")
	}
	if pkt[5] != 0xe0 {
		return r, errors.New("not an X.224 connection request")
	}
	copy(r.SrcRef[:], pkt[8:10])
	end := 5 + int(pkt[4]) // LI counts the bytes after itself
	if end > len(pkt) {
		end = len(pkt)
	}
	if end < 11 {
		end = 11
	}
	v := pkt[11:end]
	if bytes.HasPrefix(v, []byte("Cookie:")) {
		r.Cookie = true
		line := v
		if i := bytes.Index(v, []byte("\r\n")); i >= 0 {
			line, v = v[:i], v[i+2:]
		} else {
			v = nil
		}
		if bytes.HasPrefix(line, []byte(rdpCookie)) {
			r.User = cleanStr(string(line[len(rdpCookie):]), 64)
		}
	}
	if len(v) >= 8 && v[0] == 1 && binary.LittleEndian.Uint16(v[2:]) == 8 {
		r.HasNeg = true
		r.Protocols = binary.LittleEndian.Uint32(v[4:])
	}
	return r, nil
}

// rdpConfirm builds the Connection Confirm, selecting standard RDP security.
func rdpConfirm(req rdpRequest) []byte {
	if !req.HasNeg {
		return []byte{3, 0, 0, 11, 6, 0xd0, req.SrcRef[0], req.SrcRef[1], 0x12, 0x34, 0}
	}
	return []byte{
		3, 0, 0, 19,
		14, 0xd0, req.SrcRef[0], req.SrcRef[1], 0x12, 0x34, 0,
		0x02, 0x00, 0x08, 0x00, 0, 0, 0, 0, // RDP_NEG_RSP: selected protocol 0 (standard)
	}
}

func readTPKT(c net.Conn, raw *rawBuf) ([]byte, error) {
	h, err := readN(c, raw, 4)
	if err != nil {
		return h, err
	}
	l := int(binary.BigEndian.Uint16(h[2:]))
	if h[0] != 3 || l < 4 || l > rdpMaxTPKT {
		return h, errPacketTooLarge
	}
	body, err := readN(c, raw, l-4)
	return append(h, body...), err
}

// rdpHandler parses the X.224 Connection Request (mstshash cookie, requested
// protocols), confirms with standard RDP security, then reads one more bounded
// packet (the client's MCS Connect Initial) for the capture and closes.
func rdpHandler(_ context.Context, c net.Conn, _ string) Result {
	raw := &rawBuf{}
	c.SetReadDeadline(timeIn(emuReadTimeout))
	pkt, err := readTPKT(c, raw)
	if err != nil {
		if errors.Is(err, errPacketTooLarge) {
			drainMore(c, raw, 512)
			return Result{Data: raw.b, Detail: "rdp: non-RDP or oversized first packet", Tags: Classify(string(raw.b), "")}
		}
		return Result{Data: raw.b, Detail: "rdp: connection, no connection request"}
	}
	req, perr := parseRDPConnReq(pkt)
	if perr != nil {
		return Result{Data: raw.b, Detail: "rdp: malformed connection request", Tags: Classify(string(raw.b), "")}
	}
	meta := map[string]string{"requested_protocols": "standard"}
	if req.HasNeg {
		meta["requested_protocols"] = rdpProtocolNames(req.Protocols)
	}
	var tags []string
	if req.User != "" {
		meta["user"] = req.User
		tags = userTags(req.User) // a bare username is not a credential-attempt
	}
	detail := "rdp: connection request"
	if writeAll(c, rdpConfirm(req)) == nil {
		c.SetReadDeadline(timeIn(emuReadTimeout / 2))
		if _, err := readTPKT(c, raw); err == nil {
			detail = "rdp: connection request, client continued after confirm"
		}
	}
	return Result{Data: raw.b, Detail: detail, Tags: tags, Meta: meta}
}
