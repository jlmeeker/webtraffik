package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// ── MQTT ──────────────────────────────────────────────────────────────────────

const mqttMaxPacket = 4096 // largest remaining-length we accept

type mqttConnect struct {
	Proto     string
	Level     byte
	Flags     byte
	KeepAlive int
	ClientID  string
	WillTopic string
	User      string
	Pass      string
	HasUser   bool
	HasPass   bool
}

// mqttVarint decodes an MQTT variable byte integer (max 4 bytes).
func mqttVarint(b []byte) (v, n int, ok bool) {
	mult := 1
	for n < 4 {
		if n >= len(b) {
			return 0, 0, false
		}
		d := int(b[n])
		n++
		v += (d & 0x7f) * mult
		if d&0x80 == 0 {
			return v, n, true
		}
		mult *= 128
	}
	return 0, 0, false
}

// mqttStr reads a 2-byte-length-prefixed field.
func mqttStr(b []byte) (s string, rest []byte, ok bool) {
	if len(b) < 2 {
		return "", b, false
	}
	n := be16(b)
	if n > len(b)-2 {
		return "", b, false
	}
	return string(b[2 : 2+n]), b[2+n:], true
}

// parseMQTTConnect decodes a CONNECT packet body (after the fixed header).
// Fields parsed before a truncation are returned along with the error.
func parseMQTTConnect(b []byte) (m mqttConnect, err error) {
	var ok bool
	if m.Proto, b, ok = mqttStr(b); !ok {
		return m, errors.New("bad protocol name")
	}
	if len(b) < 4 {
		return m, errors.New("short connect header")
	}
	m.Level, m.Flags, m.KeepAlive = b[0], b[1], be16(b[2:])
	b = b[4:]
	if m.Level >= 5 { // skip CONNECT properties
		pl, n, ok := mqttVarint(b)
		if !ok || pl > len(b)-n {
			return m, errors.New("bad connect properties")
		}
		b = b[n+pl:]
	}
	if m.ClientID, b, ok = mqttStr(b); !ok {
		return m, errors.New("bad client id")
	}
	if m.Flags&0x04 != 0 { // will
		if m.Level >= 5 {
			pl, n, ok := mqttVarint(b)
			if !ok || pl > len(b)-n {
				return m, errors.New("bad will properties")
			}
			b = b[n+pl:]
		}
		if m.WillTopic, b, ok = mqttStr(b); !ok {
			return m, errors.New("bad will topic")
		}
		if _, b, ok = mqttStr(b); !ok {
			return m, errors.New("bad will payload")
		}
	}
	if m.Flags&0x80 != 0 {
		if m.User, b, ok = mqttStr(b); !ok {
			return m, errors.New("bad username")
		}
		m.HasUser = true
	}
	if m.Flags&0x40 != 0 {
		if m.Pass, _, ok = mqttStr(b); !ok {
			return m, errors.New("bad password")
		}
		m.HasPass = true
	}
	return m, nil
}

// readMQTTPacket reads one control packet. The remaining length is validated
// before the body is read.
func readMQTTPacket(c net.Conn, raw *rawBuf) (typ byte, body []byte, err error) {
	h, err := readN(c, raw, 1)
	if err != nil {
		return 0, nil, err
	}
	typ = h[0] >> 4
	var lenBytes []byte
	for i := 0; i < 4; i++ {
		b, err := readN(c, raw, 1)
		if err != nil {
			return typ, nil, err
		}
		lenBytes = append(lenBytes, b[0])
		if b[0]&0x80 == 0 {
			break
		}
	}
	l, _, ok := mqttVarint(lenBytes)
	if !ok || l > mqttMaxPacket {
		return typ, nil, errPacketTooLarge
	}
	body, err = readN(c, raw, l)
	return typ, body, err
}

// mqttHandler records the CONNECT (client id, credentials) and answers
// CONNACK "not authorized".
func mqttHandler(_ context.Context, c net.Conn, _ string) Result {
	raw := &rawBuf{}
	c.SetReadDeadline(timeIn(emuReadTimeout))
	typ, body, err := readMQTTPacket(c, raw)
	if err != nil || typ != 1 {
		if errors.Is(err, errPacketTooLarge) || (err == nil && typ != 1) {
			drainMore(c, raw, 512)
			return Result{Data: raw.b, Detail: "mqtt: first packet is not a valid CONNECT", Tags: Classify(string(raw.b), "")}
		}
		return Result{Data: raw.b, Detail: "mqtt: connection, no CONNECT"}
	}
	m, perr := parseMQTTConnect(body)
	meta := map[string]string{}
	if m.Proto != "" {
		meta["mqtt_protocol"] = cleanStr(m.Proto, 16)
		meta["mqtt_level"] = strconv.Itoa(int(m.Level))
	}
	if m.ClientID != "" {
		meta["client_id"] = cleanStr(m.ClientID, 128)
	}
	if m.WillTopic != "" {
		meta["will_topic"] = cleanStr(m.WillTopic, 128)
	}
	var tags []string
	if m.HasUser {
		meta["user"] = cleanStr(m.User, 128)
	}
	if m.HasPass {
		meta["secret"] = cleanStr(m.Pass, maxMetaValue)
	}
	if m.HasUser || m.HasPass {
		tags = credTags(m.User, m.Pass)
	}
	// CONNACK: 3.1/3.1.1 return code 5 (not authorized); v5 reason 0x87 (the
	// v5 equivalent — code 5 is not valid there).
	connack := []byte{0x20, 0x02, 0x00, 0x05}
	if m.Level >= 5 {
		connack = []byte{0x20, 0x03, 0x00, 0x87, 0x00}
	}
	writeAll(c, connack)
	detail := fmt.Sprintf("mqtt: CONNECT %s v%d, not authorized", cleanStr(m.Proto, 16), m.Level)
	if perr != nil {
		detail = "mqtt: malformed CONNECT, not authorized"
	}
	return Result{Data: raw.b, Detail: detail, Tags: tags, Meta: meta}
}
