package services

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ── MySQL ─────────────────────────────────────────────────────────────────────

const (
	mysqlMaxPacket = 8192 // largest client packet we will read

	mysqlCapProtocol41   = 0x00000200
	mysqlCapConnectDB    = 0x00000008
	mysqlCapSSL          = 0x00000800
	mysqlCapSecureConn   = 0x00008000
	mysqlCapPluginAuth   = 0x00080000
	mysqlCapLenencClient = 0x00200000
)

var errPacketTooLarge = errors.New("packet too large")

func mysqlFrame(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// mysqlGreeting builds the v10 initial handshake payload.
func mysqlGreeting(salt []byte, connID uint32) []byte {
	p := []byte{0x0a}
	p = append(p, "8.0.35-0ubuntu0.22.04.1\x00"...)
	p = binary.LittleEndian.AppendUint32(p, connID)
	p = append(p, salt[:8]...)
	p = append(p, 0)
	// capabilities (lower): LONG_PASSWORD|FOUND_ROWS|LONG_FLAG|CONNECT_WITH_DB|
	// PROTOCOL_41|TRANSACTIONS|SECURE_CONNECTION — no SSL, so clients stay plaintext.
	p = binary.LittleEndian.AppendUint16(p, 0xa20f)
	p = append(p, 0xff)                             // utf8mb4
	p = binary.LittleEndian.AppendUint16(p, 0x02)   // SERVER_STATUS_AUTOCOMMIT
	p = binary.LittleEndian.AppendUint16(p, 0x00ff) // capabilities (upper): MULTI_*, PLUGIN_AUTH, ...
	p = append(p, 21)                               // auth-plugin-data length
	p = append(p, make([]byte, 10)...)
	p = append(p, salt[8:20]...)
	p = append(p, 0)
	p = append(p, "mysql_native_password\x00"...)
	return p
}

// readMySQLPacket reads one framed packet. A claimed length above max is
// rejected after reading only the 4-byte header.
func readMySQLPacket(r io.Reader, raw *rawBuf, max int) (seq byte, payload []byte, err error) {
	var h [4]byte
	n, err := io.ReadFull(r, h[:])
	raw.add(h[:n])
	if err != nil {
		return 0, nil, err
	}
	l := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if l > max {
		return h[3], nil, errPacketTooLarge
	}
	payload = make([]byte, l)
	n, err = io.ReadFull(r, payload)
	raw.add(payload[:n])
	return h[3], payload[:n], err
}

type mysqlHandshake struct {
	Caps       uint32
	User, DB   string
	Plugin     string
	Auth       []byte
	SSLRequest bool
}

// parseMySQLHandshake decodes a HandshakeResponse41 (or the old 320 form).
// Fields parsed before a truncation are still returned alongside the error.
func parseMySQLHandshake(p []byte) (hs mysqlHandshake, err error) {
	if len(p) < 5 {
		return hs, errors.New("short handshake response")
	}
	low := uint32(binary.LittleEndian.Uint16(p))
	if low&mysqlCapProtocol41 == 0 { // protocol 320: caps(2) maxpkt(3) user\0 auth\0 [db\0]
		hs.Caps = low
		hs.User, _, _ = cstr(p[5:])
		return hs, nil
	}
	if len(p) < 32 {
		return hs, errors.New("short handshake response")
	}
	hs.Caps = binary.LittleEndian.Uint32(p)
	if hs.Caps&mysqlCapSSL != 0 && len(p) == 32 {
		hs.SSLRequest = true
		return hs, nil
	}
	rest := p[32:]
	var ok bool
	if hs.User, rest, ok = cstr(rest); !ok {
		return hs, errors.New("unterminated username")
	}
	switch {
	case hs.Caps&mysqlCapLenencClient != 0:
		if len(rest) == 0 {
			return hs, errors.New("missing auth response")
		}
		var n int
		switch b := rest[0]; {
		case b < 0xfb:
			n, rest = int(b), rest[1:]
		case b == 0xfc && len(rest) >= 3:
			n, rest = int(binary.LittleEndian.Uint16(rest[1:])), rest[3:]
		case b == 0xfd && len(rest) >= 4:
			n, rest = int(rest[1])|int(rest[2])<<8|int(rest[3])<<16, rest[4:]
		default:
			return hs, errors.New("bad length-encoded auth length")
		}
		if n > len(rest) {
			return hs, errors.New("auth length exceeds packet")
		}
		hs.Auth, rest = rest[:n], rest[n:]
	case hs.Caps&mysqlCapSecureConn != 0:
		if len(rest) == 0 {
			return hs, errors.New("missing auth response")
		}
		n := int(rest[0])
		rest = rest[1:]
		if n > len(rest) {
			return hs, errors.New("auth length exceeds packet")
		}
		hs.Auth, rest = rest[:n], rest[n:]
	default:
		var a string
		a, rest, _ = cstr(rest)
		hs.Auth = []byte(a)
	}
	if hs.Caps&mysqlCapConnectDB != 0 {
		hs.DB, rest, _ = cstr(rest)
	}
	if hs.Caps&mysqlCapPluginAuth != 0 {
		hs.Plugin, _, _ = cstr(rest)
	}
	return hs, nil
}

func mysqlErr(user, host string, usedPassword bool) []byte {
	using := "NO"
	if usedPassword {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", cleanStr(user, 48), host, using)
	p := []byte{0xff, 0x15, 0x04, '#'} // error 1045
	p = append(p, "28000"...)
	return append(p, msg...)
}

// mysqlHandler sends a v10 greeting, records the client's handshake response
// (user, database, auth plugin, auth hash) and refuses with ERR 1045.
func mysqlHandler(_ context.Context, c net.Conn, srcIP string) Result {
	raw := &rawBuf{}
	meta := map[string]string{}
	salt := randNonZero(20)
	if writeAll(c, mysqlFrame(0, mysqlGreeting(salt, uint32(randNonZero(3)[0])+1000))) != nil {
		return Result{Detail: "mysql: client gone before greeting"}
	}
	c.SetReadDeadline(timeIn(emuReadTimeout))
	seq, payload, err := readMySQLPacket(c, raw, mysqlMaxPacket)
	if err != nil {
		if errors.Is(err, errPacketTooLarge) {
			drainMore(c, raw, 512)
			return Result{Data: raw.b, Detail: "mysql: oversized or non-MySQL first packet", Tags: Classify(string(raw.b), "")}
		}
		return Result{Data: raw.b, Detail: "mysql: connection, no handshake response"}
	}
	hs, perr := parseMySQLHandshake(payload)
	if hs.SSLRequest {
		meta["tls_requested"] = "true"
		return Result{Data: raw.b, Detail: "mysql: SSL requested (not offered)", Meta: meta}
	}
	if perr != nil && hs.User == "" {
		return Result{Data: raw.b, Detail: "mysql: malformed handshake response", Meta: meta}
	}
	meta["user"] = cleanStr(hs.User, 64)
	if hs.DB != "" {
		meta["db"] = cleanStr(hs.DB, 64)
	}
	if hs.Plugin != "" {
		meta["auth_plugin"] = cleanStr(hs.Plugin, 64)
	}
	if len(hs.Auth) > 0 {
		meta["auth_hash_hex"] = hexCap(hs.Auth, maxHashHexBytes)
	}
	writeAll(c, mysqlFrame(seq+1, mysqlErr(hs.User, srcIP, len(hs.Auth) > 0)))
	return Result{
		Data:   raw.b,
		Detail: "mysql: login attempt, access denied",
		Tags:   mergeTags([]string{"credential-attempt"}, userTags(hs.User)),
		Meta:   meta,
	}
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

const (
	pgMaxMessage   = 8192
	pgMaxPassword  = 1024
	pgMaxParams    = 32
	pgSSLRequest   = 80877103
	pgCancel       = 80877102
	pgGSSENC       = 80877104
	pgProtoVersion = 3
)

// pgReadStartup reads an untyped startup-phase message: int32 length (which
// includes itself) followed by an int32 code and parameters.
func pgReadStartup(c net.Conn, raw *rawBuf) (code uint32, body []byte, err error) {
	h, err := readN(c, raw, 4)
	if err != nil {
		return 0, nil, err
	}
	l := int(binary.BigEndian.Uint32(h))
	if l < 8 || l > pgMaxMessage {
		return 0, nil, errPacketTooLarge
	}
	body, err = readN(c, raw, l-4)
	if err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(body), body[4:], nil
}

// pgParseParams decodes the key\0value\0...\0 list of a StartupMessage.
func pgParseParams(b []byte) map[string]string {
	out := map[string]string{}
	for i := 0; i < pgMaxParams && len(b) > 0 && b[0] != 0; i++ {
		var k, v string
		k, b, _ = cstr(b)
		v, b, _ = cstr(b)
		out[cleanStr(k, 64)] = cleanStr(v, 128)
	}
	return out
}

func pgError(sqlstate, msg string) []byte {
	f := []byte{'S'}
	f = append(f, "FATAL\x00V"...)
	f = append(f, "FATAL\x00C"...)
	f = append(f, sqlstate...)
	f = append(f, 0, 'M')
	f = append(f, msg...)
	f = append(f, 0, 0)
	out := []byte{'E'}
	out = binary.BigEndian.AppendUint32(out, uint32(4+len(f)))
	return append(out, f...)
}

// postgresHandler answers SSL/GSS requests with 'N', takes the StartupMessage,
// asks for a cleartext password, records it and fails with 28P01.
func postgresHandler(_ context.Context, c net.Conn, _ string) Result {
	raw := &rawBuf{}
	meta := map[string]string{}
	var params map[string]string
	for i := 0; i < 4 && params == nil; i++ {
		c.SetReadDeadline(timeIn(emuReadTimeout))
		code, body, err := pgReadStartup(c, raw)
		if err != nil {
			if errors.Is(err, errPacketTooLarge) {
				drainMore(c, raw, 512)
				return Result{Data: raw.b, Detail: "postgres: invalid or non-PostgreSQL first message", Tags: Classify(string(raw.b), "")}
			}
			break
		}
		switch {
		case code == pgSSLRequest || code == pgGSSENC:
			meta["tls_requested"] = "true"
			if writeAll(c, []byte("N")) != nil {
				return Result{Data: raw.b, Detail: "postgres: client gone", Meta: meta}
			}
		case code == pgCancel:
			return Result{Data: raw.b, Detail: "postgres: cancel request", Meta: meta}
		case code>>16 == pgProtoVersion:
			params = pgParseParams(body)
			meta["pg_protocol"] = fmt.Sprintf("%d.%d", code>>16, code&0xffff)
		default:
			writeAll(c, pgError("0A000", fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", code>>16, code&0xffff)))
			meta["pg_protocol"] = fmt.Sprintf("%d.%d", code>>16, code&0xffff)
			return Result{Data: raw.b, Detail: "postgres: unsupported protocol version", Meta: meta}
		}
	}
	if params == nil {
		return Result{Data: raw.b, Detail: "postgres: connection, no startup message", Meta: meta}
	}
	user := params["user"]
	meta["user"] = user
	if v := params["database"]; v != "" {
		meta["db"] = v
	}
	if v := params["application_name"]; v != "" {
		meta["application_name"] = v
	}
	res := Result{Data: raw.b, Detail: "postgres: startup", Meta: meta}

	// AuthenticationCleartextPassword
	if writeAll(c, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) != nil {
		return res
	}
	c.SetReadDeadline(timeIn(emuReadTimeout))
	hdr, err := readN(c, raw, 5)
	res.Data = raw.b
	if err != nil || hdr[0] != 'p' {
		res.Detail = "postgres: startup, no password"
		return res
	}
	l := int(binary.BigEndian.Uint32(hdr[1:]))
	if l < 5 || l > pgMaxPassword {
		res.Detail = "postgres: startup, oversized password message"
		return res
	}
	body, err := readN(c, raw, l-4)
	res.Data = raw.b
	if err != nil {
		res.Detail = "postgres: startup, truncated password message"
		return res
	}
	secret, _, _ := cstr(body)
	meta["secret"] = cleanStr(secret, maxMetaValue)
	res.Detail = "postgres: login attempt, password authentication failed"
	res.Tags = credTags(user, secret)
	writeAll(c, pgError("28P01", fmt.Sprintf("password authentication failed for user %q", cleanStr(user, 48))))
	return res
}
