package services

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── harness ───────────────────────────────────────────────────────────────────

const testSrcIP = "198.51.100.7"

// runPipe runs h on one end of a net.Pipe and the client func on the other.
func runPipe(t *testing.T, h ConnHandler, client func(c net.Conn)) Result {
	t.Helper()
	srv, cli := net.Pipe()
	cli.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan Result, 1)
	go func() { defer srv.Close(); done <- h(context.Background(), srv, testSrcIP) }()
	client(cli)
	cli.Close()
	select {
	case r := <-done:
		return r
	case <-time.After(8 * time.Second):
		t.Fatal("handler did not return")
		return Result{}
	}
}

// feed sends hostile bytes and closes; the handler must return promptly with
// bounded output and must not panic.
func feed(t *testing.T, h ConnHandler, payload []byte) Result {
	t.Helper()
	srv, cli := net.Pipe()
	done := make(chan Result, 1)
	go func() { defer srv.Close(); done <- h(context.Background(), srv, testSrcIP) }()
	go io.Copy(io.Discard, cli)
	go func() { cli.Write(payload); cli.Close() }()
	select {
	case r := <-done:
		checkBounded(t, r)
		return r
	case <-time.After(8 * time.Second):
		t.Fatalf("handler did not return for %d-byte input", len(payload))
		return Result{}
	}
}

func checkBounded(t *testing.T, r Result) {
	t.Helper()
	if len(r.Data) > maxClientData {
		t.Errorf("Data not capped: %d bytes", len(r.Data))
	}
	if r.Detail == "" {
		t.Error("empty Detail")
	}
	if len(r.Detail) > 300 {
		t.Errorf("Detail too long: %d", len(r.Detail))
	}
	for k, v := range r.Meta {
		if len(v) > 2*maxMetaValue {
			t.Errorf("meta %q too long: %d", k, len(v))
		}
	}
}

// hostileInputs returns inputs shared by every parser test.
func hostileInputs() [][]byte {
	rng := rand.New(rand.NewSource(1))
	random := func(n int) []byte { b := make([]byte, n); rng.Read(b); return b }
	return [][]byte{
		nil,
		{0},
		{0xff},
		{0xff, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0xff}, 4096),
		bytes.Repeat([]byte{0}, 4096),
		random(7), random(64), random(1500), random(20000),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("${jndi:ldap://x/a}"),
	}
}

func readFull(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

func metaHas(t *testing.T, m map[string]string, k, want string) {
	t.Helper()
	if m[k] != want {
		t.Errorf("meta[%q] = %q, want %q (all: %v)", k, m[k], want, m)
	}
}

func noSecretsInDetail(t *testing.T, r Result, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(r.Detail, s) {
			t.Errorf("Detail %q leaks %q", r.Detail, s)
		}
	}
}

// ── MySQL ─────────────────────────────────────────────────────────────────────

func mysqlClientResponse(caps uint32, user string, auth []byte, db, plugin string) []byte {
	p := binary.LittleEndian.AppendUint32(nil, caps)
	p = binary.LittleEndian.AppendUint32(p, 1<<24)
	p = append(p, 0x21)
	p = append(p, make([]byte, 23)...)
	p = append(p, user...)
	p = append(p, 0)
	p = append(p, byte(len(auth)))
	p = append(p, auth...)
	p = append(p, db...)
	p = append(p, 0)
	p = append(p, plugin...)
	p = append(p, 0)
	return p
}

func readMySQLFrame(t *testing.T, c net.Conn) (byte, []byte) {
	t.Helper()
	h := readFull(t, c, 4)
	l := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	return h[3], readFull(t, c, l)
}

func TestMySQLEmulator(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 20)
	res := runPipe(t, mysqlHandler, func(c net.Conn) {
		seq, g := readMySQLFrame(t, c)
		if seq != 0 || g[0] != 10 {
			t.Fatalf("greeting seq=%d proto=%d", seq, g[0])
		}
		ver, rest, ok := cstr(g[1:])
		if !ok || !strings.HasPrefix(ver, "8.0.") {
			t.Fatalf("version = %q", ver)
		}
		// connid(4) salt1(8) filler(1) caps(2) charset(1) status(2) caps(2) authlen(1) reserved(10) salt2(13) plugin
		if len(rest) < 4+8+1+2+1+2+2+1+10+13 {
			t.Fatalf("greeting too short: %d", len(rest))
		}
		if rest[4+8] != 0 || rest[4+8+1+2+1+2+2] != 21 {
			t.Errorf("greeting layout wrong: filler/authlen = %d/%d", rest[12], rest[20])
		}
		if !bytes.HasSuffix(rest, []byte("mysql_native_password\x00")) {
			t.Error("greeting lacks auth plugin name")
		}
		caps := uint32(0x200 | 0x8 | 0x8000 | 0x80000)
		resp := mysqlClientResponse(caps, "root", hash, "mysql", "mysql_native_password")
		c.Write(append([]byte{byte(len(resp)), byte(len(resp) >> 8), 0, 1}, resp...))
		seq, e := readMySQLFrame(t, c)
		if seq != 2 || e[0] != 0xff || binary.LittleEndian.Uint16(e[1:]) != 1045 || string(e[3:9]) != "#28000" {
			t.Fatalf("error packet wrong: seq=%d % x", seq, e[:9])
		}
		if !strings.Contains(string(e[9:]), "Access denied for user 'root'@'"+testSrcIP+"' (using password: YES)") {
			t.Errorf("message = %q", e[9:])
		}
	})
	metaHas(t, res.Meta, "user", "root")
	metaHas(t, res.Meta, "db", "mysql")
	metaHas(t, res.Meta, "auth_plugin", "mysql_native_password")
	metaHas(t, res.Meta, "auth_hash_hex", strings.Repeat("ab", 20))
	if _, ok := res.Meta["secret"]; ok {
		t.Error("MySQL must not record a secret, only the hash")
	}
	if !hasTag(res.Tags, "credential-attempt") || !hasTag(res.Tags, "privileged-user") {
		t.Errorf("tags = %v", res.Tags)
	}
	if hasTag(res.Tags, "mirai-default-creds") {
		t.Errorf("root + auth hash must not be tagged as a Mirai default password: %v", res.Tags)
	}
	noSecretsInDetail(t, res, "root", strings.Repeat("ab", 20))
	checkBounded(t, res)
}

func TestMySQLParserBounds(t *testing.T) {
	caps := uint32(0x200 | 0x8 | 0x8000 | 0x80000)
	lenenc := caps | mysqlCapLenencClient
	base := func(c uint32, tail []byte) []byte {
		p := binary.LittleEndian.AppendUint32(nil, c)
		p = append(p, make([]byte, 28)...)
		return append(p, tail...)
	}
	cases := map[string][]byte{
		"empty":                  nil,
		"short":                  {0x0f, 0x02, 0, 0},
		"caps only":              base(caps, nil),
		"unterminated user":      base(caps, []byte("rootrootroot")),
		"auth len > packet":      base(caps, append([]byte("u\x00"), 0xff, 'a', 'b')),
		"lenenc 0xfe (8 byte)":   base(lenenc, append([]byte("u\x00"), 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f)),
		"lenenc 0xfc huge":       base(lenenc, append([]byte("u\x00"), 0xfc, 0xff, 0xff, 'a')),
		"lenenc 0xfd huge":       base(lenenc, append([]byte("u\x00"), 0xfd, 0xff, 0xff, 0xff, 'a')),
		"lenenc truncated":       base(lenenc, append([]byte("u\x00"), 0xfc)),
		"no db terminator":       base(caps, append([]byte("u\x00\x00"), []byte("dbdbdb")...)),
		"garbage":                bytes.Repeat([]byte{0xff}, 600),
		"old protocol":           {0x0f, 0x00, 0, 0, 0, 'b', 'o', 'b', 0, 'x'},
		"ssl request":            base(caps|mysqlCapSSL, nil)[:32],
		"overlong user":          base(caps, append(bytes.Repeat([]byte("A"), 5000), 0, 0)),
		"high bytes in username": base(caps, []byte("\xff\xfe\x01\x00\x00")),
	}
	for name, in := range cases {
		hs, _ := parseMySQLHandshake(in) // must not panic
		if len(hs.Auth) > len(in) {
			t.Errorf("%s: auth longer than input", name)
		}
	}
	// A header claiming 16 MiB must be refused after reading the header only.
	r := bytes.NewReader(append([]byte{0xff, 0xff, 0xff, 0}, make([]byte, 100000)...))
	raw := &rawBuf{}
	if _, _, err := readMySQLPacket(r, raw, mysqlMaxPacket); err != errPacketTooLarge {
		t.Errorf("err = %v, want errPacketTooLarge", err)
	}
	if r.Len() < 100000 {
		t.Errorf("read %d body bytes of an oversized packet", 100000-r.Len())
	}
	for _, in := range hostileInputs() {
		feed(t, mysqlHandler, in)
	}
	// "GET /" parses as a ~5 MiB packet length: recorded and classified, not read.
	res := feed(t, mysqlHandler, []byte("GET /../../etc/passwd HTTP/1.1\r\n\r\n"))
	if !hasTag(res.Tags, "path-traversal") {
		t.Errorf("wrong-protocol probe not classified: %v", res.Tags)
	}
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

func pgMsgBytes(code uint32, params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, code)
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	if len(params) > 0 {
		body = append(body, 0)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...)
}

func TestPostgresEmulator(t *testing.T) {
	res := runPipe(t, postgresHandler, func(c net.Conn) {
		c.Write(pgMsgBytes(pgSSLRequest))
		if b := readFull(t, c, 1); b[0] != 'N' {
			t.Fatalf("SSLRequest reply = %q, want N", b)
		}
		c.Write(pgMsgBytes(196608, "user", "dbadmin", "database", "app", "application_name", "psql"))
		auth := readFull(t, c, 9)
		if !bytes.Equal(auth, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
			t.Fatalf("auth request = % x, want cleartext password", auth)
		}
		pw := append([]byte("hunter2"), 0)
		c.Write(append([]byte{'p', 0, 0, 0, byte(4 + len(pw))}, pw...))
		h := readFull(t, c, 5)
		if h[0] != 'E' {
			t.Fatalf("final message type %q, want E", h[0])
		}
		body := readFull(t, c, int(binary.BigEndian.Uint32(h[1:]))-4)
		if !bytes.Contains(body, []byte("C28P01\x00")) || !bytes.Contains(body, []byte("SFATAL")) {
			t.Errorf("ErrorResponse = %q", body)
		}
	})
	metaHas(t, res.Meta, "user", "dbadmin")
	metaHas(t, res.Meta, "db", "app")
	metaHas(t, res.Meta, "application_name", "psql")
	metaHas(t, res.Meta, "secret", "hunter2")
	if !hasTag(res.Tags, "credential-attempt") {
		t.Errorf("tags = %v", res.Tags)
	}
	noSecretsInDetail(t, res, "hunter2", "dbadmin")
	checkBounded(t, res)
}

func TestPostgresBounds(t *testing.T) {
	huge := binary.BigEndian.AppendUint32(nil, 0x7fffffff)
	huge = append(huge, bytes.Repeat([]byte{'A'}, 20000)...)
	startup := pgMsgBytes(196608, "user", "u")
	pwHuge := append(append([]byte{}, startup...), 'p', 0x7f, 0xff, 0xff, 0xff)
	pwHuge = append(pwHuge, bytes.Repeat([]byte{'B'}, 20000)...)
	manyParams := make([]string, 0, 400)
	for i := 0; i < 200; i++ {
		manyParams = append(manyParams, "k", "v")
	}
	inputs := [][]byte{
		huge,
		{0, 0, 0, 3},             // length below minimum
		{0, 0, 0, 8},             // truncated after length
		pgMsgBytes(196608)[:6],   // truncated mid-code
		startup[:len(startup)-3], // truncated params
		pwHuge,                   // password message claiming 2 GiB
		append(append([]byte{}, startup...), 'p'),  // truncated password header
		append(pgMsgBytes(pgSSLRequest), huge...),  // SSL then garbage
		bytes.Repeat(pgMsgBytes(pgSSLRequest), 50), // SSLRequest flood
		pgMsgBytes(196608, manyParams...),          // 200 params
		pgMsgBytes(0x00020000, "user", "x"),        // protocol 2.0
		pgMsgBytes(pgCancel),
		pgMsgBytes(196608, "user", strings.Repeat("\x01\xff", 5000)), // control bytes, oversized value
	}
	for _, in := range inputs {
		feed(t, postgresHandler, in)
	}
	for _, in := range hostileInputs() {
		feed(t, postgresHandler, in)
	}
	if got := pgParseParams(bytes.Repeat([]byte("kk\x00vv\x00"), 1000)); len(got) > pgMaxParams {
		t.Errorf("pgParseParams returned %d params", len(got))
	}
	res := feed(t, postgresHandler, huge)
	if len(res.Data) > 4+512 {
		t.Errorf("oversized message read %d bytes", len(res.Data))
	}
	res = feed(t, postgresHandler, pgMsgBytes(0x00020000, "user", "x"))
	metaHas(t, res.Meta, "pg_protocol", "2.0")
}

// ── MQTT ──────────────────────────────────────────────────────────────────────

func mqttStrB(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }

func mqttConnectPkt(level byte, flags byte, clientID, user, pass string) []byte {
	name := "MQTT"
	if level == 3 {
		name = "MQIsdp"
	}
	body := mqttStrB(name)
	body = append(body, level, flags, 0, 60)
	if level >= 5 {
		body = append(body, 0) // no properties
	}
	body = append(body, mqttStrB(clientID)...)
	if flags&0x80 != 0 {
		body = append(body, mqttStrB(user)...)
	}
	if flags&0x40 != 0 {
		body = append(body, mqttStrB(pass)...)
	}
	return append([]byte{0x10, byte(len(body))}, body...)
}

func TestMQTTEmulator(t *testing.T) {
	for _, tc := range []struct {
		level byte
		want  []byte
	}{{4, []byte{0x20, 0x02, 0x00, 0x05}}, {3, []byte{0x20, 0x02, 0x00, 0x05}}, {5, []byte{0x20, 0x03, 0x00, 0x87, 0x00}}} {
		res := runPipe(t, mqttHandler, func(c net.Conn) {
			c.Write(mqttConnectPkt(tc.level, 0xc2, "cam-01", "admin", "s3cret"))
			if got := readFull(t, c, len(tc.want)); !bytes.Equal(got, tc.want) {
				t.Errorf("level %d CONNACK = % x, want % x", tc.level, got, tc.want)
			}
		})
		metaHas(t, res.Meta, "client_id", "cam-01")
		metaHas(t, res.Meta, "user", "admin")
		metaHas(t, res.Meta, "secret", "s3cret")
		metaHas(t, res.Meta, "mqtt_level", string(rune('0'+tc.level)))
		if !hasTag(res.Tags, "credential-attempt") || !hasTag(res.Tags, "privileged-user") {
			t.Errorf("tags = %v", res.Tags)
		}
		noSecretsInDetail(t, res, "s3cret", "admin")
		checkBounded(t, res)
	}
	// Anonymous connect: no credential tag, still refused.
	res := runPipe(t, mqttHandler, func(c net.Conn) {
		c.Write(mqttConnectPkt(4, 0x02, "x", "", ""))
		readFull(t, c, 4)
	})
	if hasTag(res.Tags, "credential-attempt") || res.Meta["secret"] != "" {
		t.Errorf("anonymous connect recorded credentials: %v %v", res.Tags, res.Meta)
	}
}

func TestMQTTBounds(t *testing.T) {
	good := mqttConnectPkt(4, 0xc2, "id", "u", "p")
	for n := 0; n < len(good); n++ { // every truncation
		feed(t, mqttHandler, good[:n])
	}
	inputs := [][]byte{
		{0x10, 0xff, 0xff, 0xff, 0x7f},                              // 256 MiB remaining length
		{0x10, 0xff, 0xff, 0xff, 0xff, 0xff},                        // 5-byte varint
		{0x10, 0xff, 0xff, 0x7f},                                    // 2 MiB
		{0x10, 0x04, 0xff, 0xff, 'M', 'Q'},                          // protocol name length > packet
		{0x10, 0x0a, 0, 4, 'M', 'Q', 'T', 'T', 4, 0xc2, 0, 0},       // user/pass flags, no fields
		{0x10, 0x08, 0, 4, 'M', 'Q', 'T', 'T', 5, 0x00, 0, 0},       // v5, properties missing
		{0x10, 0x09, 0, 4, 'M', 'Q', 'T', 'T', 5, 0x00, 0, 0, 0xff}, // v5, property length > packet
		{0x30, 0x03, 'a', 'b', 'c'},                                 // PUBLISH instead of CONNECT
		{0xe0, 0x00},                                                // DISCONNECT
	}
	for _, in := range inputs {
		feed(t, mqttHandler, in)
	}
	for _, in := range hostileInputs() {
		feed(t, mqttHandler, in)
	}
	for _, in := range inputs {
		parseMQTTConnect(in) // direct, must not panic
	}
	if res := feed(t, mqttHandler, inputs[0]); len(res.Data) > 5+512 {
		t.Errorf("oversized remaining length read %d bytes", len(res.Data))
	}
}

// ── RDP ───────────────────────────────────────────────────────────────────────

func rdpConnReq(variable []byte) []byte {
	li := 6 + len(variable)
	p := []byte{3, 0, byte((5 + li) >> 8), byte(5 + li), byte(li), 0xe0, 0, 0, 0x12, 0x34, 0}
	return append(p, variable...)
}

func TestRDPEmulator(t *testing.T) {
	neg := []byte{1, 0, 8, 0, 3, 0, 0, 0} // TLS | CredSSP
	req := rdpConnReq(append([]byte("Cookie: mstshash=admin\r\n"), neg...))
	res := runPipe(t, rdpHandler, func(c net.Conn) {
		c.Write(req)
		cc := readFull(t, c, 19)
		if cc[0] != 3 || cc[3] != 19 || cc[5] != 0xd0 || cc[11] != 0x02 || cc[15] != 0 {
			t.Errorf("connection confirm = % x", cc)
		}
		if cc[8] != 0x12 || cc[9] != 0x34 {
			t.Errorf("dst-ref should echo the client's src-ref: % x", cc[6:10])
		}
		c.Write([]byte{3, 0, 0, 8, 2, 0xf0, 0x80, 0x7f}) // follow-up (MCS) packet
	})
	metaHas(t, res.Meta, "user", "admin")
	metaHas(t, res.Meta, "requested_protocols", "tls,credssp")
	if !hasTag(res.Tags, "privileged-user") || hasTag(res.Tags, "credential-attempt") {
		t.Errorf("tags = %v", res.Tags)
	}
	if !strings.Contains(res.Detail, "continued") {
		t.Errorf("detail = %q", res.Detail)
	}
	noSecretsInDetail(t, res, "admin")

	// No cookie, no negotiation request: bare 11-byte confirm.
	res = runPipe(t, rdpHandler, func(c net.Conn) {
		c.Write(rdpConnReq(nil))
		cc := readFull(t, c, 11)
		if cc[3] != 11 || cc[4] != 6 {
			t.Errorf("bare confirm = % x", cc)
		}
	})
	metaHas(t, res.Meta, "requested_protocols", "standard")
	if res.Meta["user"] != "" {
		t.Error("user set without a cookie")
	}
}

func TestRDPBounds(t *testing.T) {
	good := rdpConnReq(append([]byte("Cookie: mstshash=bob\r\n"), 1, 0, 8, 0, 0, 0, 0, 0))
	for n := 0; n <= len(good); n++ {
		parseRDPConnReq(good[:n]) // must not panic
		feed(t, rdpHandler, good[:n])
	}
	inputs := [][]byte{
		{3, 0, 0xff, 0xff, 0x0e, 0xe0},                                      // TPKT claims 64 KiB
		{3, 0, 0, 3},                                                        // length below header
		{3, 0, 0, 11, 0xff, 0xe0, 0, 0, 0, 0, 0},                            // LI past end of packet
		{3, 0, 0, 11, 0, 0xe0, 0, 0, 0, 0, 0},                               // LI too small
		{3, 0, 0, 12, 7, 0xe0, 0, 0, 0, 0, 0, 1},                            // neg req truncated
		rdpConnReq([]byte("Cookie: mstshash=" + strings.Repeat("A", 3000))), // no CRLF, long
		rdpConnReq([]byte("Cookie: mstshash=\x00\x01\xff\r\n")),
		rdpConnReq([]byte("Cookie: msts=3232235521.15629.0000\r\n")),
		{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0}, // TLS ClientHello on the RDP port
		{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0xff, 0xff, 0xff, 0xff},
	}
	for _, in := range inputs {
		parseRDPConnReq(in)
		feed(t, rdpHandler, in)
	}
	for _, in := range hostileInputs() {
		parseRDPConnReq(in)
		feed(t, rdpHandler, in)
	}
	if r, err := parseRDPConnReq(inputs[5]); err != nil || len(r.User) > 64 {
		t.Errorf("long cookie: user len %d err %v", len(r.User), err)
	}
	if res := feed(t, rdpHandler, inputs[0]); len(res.Data) > 4+512 {
		t.Errorf("oversized TPKT read %d bytes", len(res.Data))
	}
	if r, _ := parseRDPConnReq(rdpConnReq(append([]byte("Cookie: mstshash=x\r\n"), 1, 0, 8, 0, 0xff, 0xff, 0xff, 0xff))); rdpProtocolNames(r.Protocols) == "" {
		t.Error("unknown protocol bits produced empty name")
	}
}

// ── SIP ───────────────────────────────────────────────────────────────────────

func sipSample(method, ua, extra string) []byte {
	return []byte(method + " sip:100@203.0.113.5 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-1234;rport\r\n" +
		"From: \"sipvicious\" <sip:100@1.1.1.1>;tag=6264313633613737313363340133383332393936\r\n" +
		"To: \"sipvicious\" <sip:100@1.1.1.1>\r\n" +
		"Call-ID: 1704290419@198.51.100.7\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		"Contact: <sip:100@198.51.100.7:5060>\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"Accept: application/sdp\r\n" + extra +
		"Content-Length: 0\r\n\r\n")
}

func TestSIPParser(t *testing.T) {
	m, err := parseSIP(sipSample("OPTIONS", "friendly-scanner", ""))
	if err != nil || m.Method != "OPTIONS" || m.URI != "sip:100@203.0.113.5" || m.H["user-agent"] != "friendly-scanner" {
		t.Fatalf("parse = %+v err %v", m, err)
	}
	if m, err := parseSIP([]byte("INVITE sip:x SIP/2.0\r\nv: SIP/2.0/UDP a\r\nf: <sip:me@x>\r\ni: abc\r\n\r\n")); err != nil || m.H["via"] == "" || m.H["from"] == "" || m.H["call-id"] != "abc" {
		t.Errorf("compact headers not expanded: %+v %v", m, err)
	}
	if m, err := parseSIP([]byte("\r\n\r\nOPTIONS sip:x SIP/2.0\r\n\r\n")); err != nil || m.Method != "OPTIONS" {
		t.Errorf("leading keepalive CRLF: %+v %v", m, err)
	}
	if m, err := parseSIP([]byte("SIP/2.0 200 OK\r\nVia: x\r\n\r\n")); err != nil || !m.IsResponse {
		t.Errorf("response not detected: %+v %v", m, err)
	}
	for _, bad := range []string{"", "\r\n", "hello", "GET / HTTP/1.1\r\n\r\n", "options sip:x\r\n\r\n", "A sip:x SIP/2.0\r\n\r\n",
		"OPTIONS\x00 sip:x SIP/2.0\r\n\r\n", strings.Repeat("A", 100000)} {
		if m, err := parseSIP([]byte(bad)); err == nil {
			t.Errorf("parseSIP(%.20q) accepted: %+v", bad, m)
		}
	}
	// header flood: bounded count and size
	flood := "OPTIONS sip:x SIP/2.0\r\n" + strings.Repeat("X-Junk: "+strings.Repeat("a", 900)+"\r\n", 5000)
	m, err = parseSIP([]byte(flood))
	if err != nil || len(m.H) > sipMaxHeaders+1 {
		t.Errorf("flood: %d headers, err %v", len(m.H), err)
	}
	for k, v := range m.H {
		if len(v) > 512 {
			t.Errorf("header %q value len %d", k, len(v))
		}
	}
	for _, in := range hostileInputs() {
		parseSIP(in)
	}
}

func TestSIPUDP(t *testing.T) {
	opt := sipSample("OPTIONS", "friendly-scanner", "")
	res := sipUDP(opt)
	metaHas(t, res.Meta, "sip_method", "OPTIONS")
	metaHas(t, res.Meta, "user_agent", "friendly-scanner")
	if !strings.Contains(res.Meta["from"], "sip:100@1.1.1.1") {
		t.Errorf("from = %q", res.Meta["from"])
	}
	for _, want := range []string{"scanner:sipvicious", "sip-scan"} {
		if !hasTag(res.Tags, want) {
			t.Errorf("tags %v lack %q", res.Tags, want)
		}
	}
	if res := sipUDP(sipSample("INVITE", "sipcli/v1.8", "")); !hasTag(res.Tags, "scanner:sipcli") {
		t.Errorf("tags = %v", res.Tags)
	}
	// A digest Authorization header yields user + hash, never in Detail.
	auth := "Authorization: Digest username=\"1001\", realm=\"asterisk\", nonce=\"abc\", uri=\"sip:x\", response=\"0123456789abcdef0123456789abcdef\"\r\n"
	res = sipUDP(sipSample("REGISTER", "Zoiper", auth))
	metaHas(t, res.Meta, "user", "1001")
	metaHas(t, res.Meta, "auth_hash_hex", "0123456789abcdef0123456789abcdef")
	noSecretsInDetail(t, res, "1001", "0123456789abcdef")
	for _, in := range hostileInputs() {
		res := sipUDP(in)
		checkBounded(t, Result{Detail: res.Detail, Meta: res.Meta}) // serveUDP clips Data to 512 bytes
	}
}

func mcFrame(id uint16, cmd string) []byte {
	return append([]byte{byte(id >> 8), byte(id), 0, 0, 0, 1, 0, 0}, cmd...)
}

func TestMemcachedUDP(t *testing.T) {
	res := memcachedUDP(mcFrame(0x1234, "stats\r\n"))
	if !hasTag(res.Tags, tagAmplification) {
		t.Errorf("stats not tagged: %v", res.Tags)
	}
	metaHas(t, res.Meta, "memcached_cmd", "stats")
	metaHas(t, res.Meta, "memcached_request_id", "1234")
	for _, cmd := range []string{"get foo\r\n", "gets a b c d\r\n", "get " + strings.Repeat("k ", 500) + "\r\n"} {
		if res := memcachedUDP(mcFrame(1, cmd)); !hasTag(res.Tags, tagAmplification) {
			t.Errorf("%.20q: tags %v", cmd, res.Tags)
		}
	}
	// set is not an amplification vector
	if res := memcachedUDP(mcFrame(3, "set k 0 0 5\r\nhello\r\n")); hasTag(res.Tags, tagAmplification) {
		t.Error("set tagged as amplification")
	}
	for _, in := range append(hostileInputs(), mcFrame(0, ""), mcFrame(0, "\r\n"), mcFrame(0, strings.Repeat("A", 2000)), mcFrame(0, "\xff\xfe\x00")) {
		res := memcachedUDP(in)
		checkBounded(t, Result{Data: res.Data, Detail: res.Detail, Meta: res.Meta})
	}
}

func TestNTPUDP(t *testing.T) {
	client := make([]byte, 48)
	client[0] = 0x23 // LI 0, v4, mode 3
	res := ntpUDP(client)
	if hasTag(res.Tags, tagAmplification) {
		t.Error("plain client request tagged as amplification")
	}
	metaHas(t, res.Meta, "ntp_mode", "3")
	if res := ntpUDP([]byte{0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0}); !hasTag(res.Tags, tagAmplification) || !strings.Contains(res.Detail, "monlist") {
		t.Errorf("monlist: %+v", res)
	}
	if res := ntpUDP([]byte{0x16, 0x02, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}); !hasTag(res.Tags, tagAmplification) {
		t.Errorf("mode 6 tags=%v", res.Tags)
	}
	for n := 0; n < 48; n++ { // every truncation: no panic
		ntpUDP(client[:n])
	}
	for _, in := range hostileInputs() {
		ntpUDP(in)
	}
}

func TestSSDPUDP(t *testing.T) {
	req := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\nUSER-AGENT: nmap/7\r\n\r\n")
	res := ssdpUDP(req)
	if !hasTag(res.Tags, tagAmplification) || !hasTag(res.Tags, "ssdp-scan") || !hasTag(res.Tags, "scanner:nmap") {
		t.Errorf("tags = %v", res.Tags)
	}
	metaHas(t, res.Meta, "ssdp_st", "ssdp:all")
	metaHas(t, res.Meta, "ssdp_method", "M-SEARCH")
	if res := ssdpUDP([]byte("NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\n\r\n")); hasTag(res.Tags, tagAmplification) {
		t.Error("NOTIFY tagged as amplification")
	}
	for _, in := range append(hostileInputs(), []byte(strings.Repeat("M-SEARCH * HTTP/1.1\r\n", 1000)), []byte(strings.Repeat("A:", 5000))) {
		ssdpUDP(in)
	}
}

// Handlers survive arbitrary input and never record more than they were sent.
func TestUDPHandlersSurviveGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	samples := hostileInputs()
	samples = append(samples, mcFrame(1, "stats\r\n"), sipSample("OPTIONS", "x", ""),
		[]byte{0x17, 0, 3, 0x2a}, make([]byte, 48), []byte("M-SEARCH * HTTP/1.1\r\n\r\n"))
	for i := 0; i < 500; i++ {
		b := make([]byte, rng.Intn(600))
		rng.Read(b)
		samples = append(samples, b)
	}
	for port, h := range udpHandlers {
		for _, in := range samples {
			if res := safeUDP(h, in); len(res.Data) > len(in) {
				t.Fatalf("port %d: result data longer than packet", port)
			}
		}
	}
}

// UDP source addresses can be forged, so a UDP listener must never write
// anything back, whatever the handler and datagram.
func TestServeUDPNeverReplies(t *testing.T) {
	e, cs := newEnv(t)
	for port, h := range map[int]udpHandler{
		123: ntpUDP, 1900: ssdpUDP, 5060: sipUDP, 11211: memcachedUDP, 53: nil,
	} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { <-ctx.Done(); pc.Close() }()
		go e.serveUDP(ctx, pc, port, h)

		cli, err := net.Dial("udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		probes := [][]byte{
			mcFrame(1, "stats\r\n"), sipSample("OPTIONS", "x", ""), sipSample("REGISTER", "x", ""),
			append([]byte{0x23}, make([]byte, 47)...), []byte("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"), []byte("hello"),
		}
		for _, p := range probes {
			cli.Write(p)
			got := cs.wait(t)
			if got.Protocol != "udp" || got.DstPort != strconv.Itoa(port) {
				t.Errorf("port %d capture = %+v", port, got)
			}
		}
		cli.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		if n, err := cli.Read(make([]byte, 2048)); err == nil {
			t.Errorf("port %d: sensor sent a %d-byte UDP reply", port, n)
		}
	}
}

// ── Elasticsearch / Docker via the HTTP honeypot ─────────────────────────────

func serveFakeOn(t *testing.T, e *Env, port string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go e.serveHTTP(ctx, ln, port, false)
	return "http://" + ln.Addr().String()
}

func doReq(t *testing.T, method, url string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestElasticsearchFake(t *testing.T) {
	e, cs := newEnv(t)
	base := serveFakeOn(t, e, "9200")

	resp, body := doReq(t, "GET", base+"/")
	var root struct {
		Version struct{ Number string } `json:"version"`
		Tagline string                  `json:"tagline"`
	}
	if err := json.Unmarshal([]byte(body), &root); err != nil || root.Version.Number == "" || root.Tagline != "You Know, for Search" {
		t.Errorf("root = %v %q", err, body)
	}
	if resp.Header.Get("X-elastic-product") != "Elasticsearch" || strings.Contains(resp.Header.Get("Server"), "nginx") {
		t.Errorf("headers = %v", resp.Header)
	}
	if got := cs.wait(t); got.Meta["path"] != "/" || got.DstPort != "9200" {
		t.Errorf("capture = %+v", got)
	}

	resp, body = doReq(t, "GET", base+"/_cat/indices?v")
	if !strings.Contains(body, ".kibana") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("_cat/indices = %q %v", body, resp.Header)
	}
	if got := cs.wait(t); got.Meta["path"] != "/_cat/indices" {
		t.Errorf("path = %q", got.Meta["path"])
	}
	_, body = doReq(t, "GET", base+"/_cat/indices?format=json")
	var idx []map[string]string
	if err := json.Unmarshal([]byte(body), &idx); err != nil || len(idx) == 0 {
		t.Errorf("json indices: %v %q", err, body)
	}
	cs.wait(t)

	resp, body = doReq(t, "GET", base+"/_nodes/\"quote\"")
	var errBody map[string]any
	if resp.StatusCode != 400 || json.Unmarshal([]byte(body), &errBody) != nil {
		t.Errorf("unknown path: %d %q", resp.StatusCode, body)
	}
	cs.wait(t)
	if resp, _ := doReq(t, "HEAD", base+"/"); resp.StatusCode != 200 {
		t.Errorf("HEAD / = %d", resp.StatusCode)
	}
	cs.wait(t)
}

func TestDockerFake(t *testing.T) {
	e, cs := newEnv(t)
	base := serveFakeOn(t, e, "2375")

	resp, body := doReq(t, "GET", base+"/version")
	var v map[string]any
	if json.Unmarshal([]byte(body), &v) != nil || v["Version"] != "25.0.3" {
		t.Errorf("/version = %q", body)
	}
	if resp.Header.Get("Api-Version") == "" || !strings.HasPrefix(resp.Header.Get("Server"), "Docker/") {
		t.Errorf("headers = %v", resp.Header)
	}
	got := cs.wait(t)
	if got.Meta["path"] != "/version" || !hasTag(got.Tags, "docker-api-probe") {
		t.Errorf("capture = %+v", got)
	}
	_, body = doReq(t, "GET", base+"/v1.44/containers/json?all=1")
	var cl []map[string]any
	if json.Unmarshal([]byte(body), &cl) != nil || len(cl) == 0 {
		t.Errorf("containers = %q", body)
	}
	if got := cs.wait(t); got.Meta["path"] != "/v1.44/containers/json" || !hasTag(got.Tags, "docker-api-probe") {
		t.Errorf("capture = %+v", got)
	}
	if _, body := doReq(t, "GET", base+"/_ping"); body != "OK" {
		t.Errorf("_ping = %q", body)
	}
	cs.wait(t)
	resp, body = doReq(t, "POST", base+"/containers/create?name=x")
	var created struct{ Id string }
	if resp.StatusCode != 201 || json.Unmarshal([]byte(body), &created) != nil || len(created.Id) != 64 {
		t.Errorf("create = %d %q", resp.StatusCode, body)
	}
	cs.wait(t)
	if resp, _ := doReq(t, "POST", base+"/containers/"+created.Id+"/start"); resp.StatusCode != 204 {
		t.Errorf("start = %d", resp.StatusCode)
	}
	cs.wait(t)
	if resp, body := doReq(t, "GET", base+"/nope"); resp.StatusCode != 404 || !strings.Contains(body, "page not found") {
		t.Errorf("unknown = %d %q", resp.StatusCode, body)
	}
	cs.wait(t)
}

// ── registry ──────────────────────────────────────────────────────────────────

func TestEmulatorPortsRegistered(t *testing.T) {
	kinds := map[PortKey]Kind{}
	for _, s := range All() {
		kinds[PortKey{s.Proto, s.Port}] = s.Kind
	}
	want := map[PortKey]Kind{
		{"tcp", 1883}: KindCustom, {"tcp", 3306}: KindCustom, {"tcp", 3389}: KindCustom,
		{"tcp", 5060}: KindCustom, {"tcp", 5432}: KindCustom,
		{"tcp", 2375}: KindHTTP, {"tcp", 9200}: KindHTTP,
		{"udp", 11211}: KindUDP, {"udp", 5060}: KindUDP, {"udp", 123}: KindUDP, {"udp", 1900}: KindUDP,
	}
	for k, kind := range want {
		if kinds[k] != kind {
			t.Errorf("%v: kind %d, want %d", k, kinds[k], kind)
		}
	}
	for port := range udpHandlers {
		if kinds[PortKey{"udp", port}] != KindUDP {
			t.Errorf("udpHandlers has port %d which is not a registered UDP listener", port)
		}
	}
	for portStr := range httpFakes {
		found := false
		for _, s := range All() {
			if s.Kind == KindHTTP && portStr == strconv.Itoa(s.Port) {
				found = true
			}
		}
		if !found {
			t.Errorf("httpFakes port %s is not an HTTP listener", portStr)
		}
	}
	if PortServiceName("1883") != "MQTT" {
		t.Error("MQTT has no display name")
	}
}

// One end-to-end pass through the real accept loop for a new emulator.
func TestMQTTThroughAcceptLoop(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveTCPOn(t, e, mqttHandler)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(mqttConnectPkt(4, 0xc2, "scanner", "root", "toor"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b := readFull(t, c, 4); b[3] != 5 {
		t.Errorf("CONNACK = % x", b)
	}
	got := cs.wait(t)
	if got.DstPort != "9999" || got.Meta["secret"] != "toor" || got.Meta["user"] != "root" {
		t.Errorf("capture = %+v", got)
	}
}
