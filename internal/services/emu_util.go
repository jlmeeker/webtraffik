package services

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// Shared helpers for the binary-protocol emulators (MySQL, PostgreSQL, MQTT,
// RDP, SIP). Every read they perform is bounded in size and time.

const (
	emuReadTimeout  = 10 * time.Second // per-read deadline inside emulators
	emuWriteTimeout = 5 * time.Second
	maxHashHexBytes = 64 // auth hashes are stored as at most this many bytes of hex
	maxMetaValue    = 256
)

// rawBuf accumulates the client bytes of a session, capped at maxClientData.
type rawBuf struct{ b []byte }

func (r *rawBuf) add(p []byte) {
	if room := maxClientData - len(r.b); room > 0 {
		r.b = append(r.b, clip(p, room)...)
	}
}

// readN reads exactly n bytes (callers bound n) and records them in raw.
func readN(c net.Conn, raw *rawBuf, n int) ([]byte, error) {
	buf := make([]byte, n)
	m, err := io.ReadFull(c, buf)
	raw.add(buf[:m])
	return buf[:m], err
}

// drainMore reads up to max further bytes (short deadline) so that an
// unrecognised first message — typically an HTTP request or other scanner
// probe aimed at the wrong port — is still captured for classification.
func drainMore(c net.Conn, raw *rawBuf, max int) {
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, max)
	n, _ := c.Read(buf)
	raw.add(buf[:n])
}

func writeAll(c net.Conn, b []byte) error {
	c.SetWriteDeadline(time.Now().Add(emuWriteTimeout))
	_, err := c.Write(b)
	return err
}

func timeIn(d time.Duration) time.Time { return time.Now().Add(d) }

// cleanStr makes a client-supplied string safe to store: control characters
// become '?', the result is cut to n bytes and is valid UTF-8.
func cleanStr(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
}

// hexCap hex-encodes at most max bytes of b.
func hexCap(b []byte, max int) string { return hex.EncodeToString(clip(b, max)) }

// credTags tags a captured login attempt.
func credTags(user, secret string) []string {
	return mergeTags([]string{"credential-attempt"}, ClassifyCreds(user, secret))
}

// userTags tags a bare username (no cleartext password to compare against).
// ClassifyCreds is deliberately not used: with an empty secret it would flag
// "root" as the Mirai empty-password default, which we know nothing about.
func userTags(user string) []string {
	if strings.EqualFold(user, "root") || strings.EqualFold(user, "admin") {
		return []string{"privileged-user"}
	}
	return nil
}

// randNonZero returns n random bytes in 1..127 (safe inside NUL-terminated
// fields such as the MySQL scramble).
func randNonZero(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = b[i]%127 + 1
	}
	return b
}

func randHex(nbytes int) string {
	b := make([]byte, nbytes)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// cstr splits a NUL-terminated string off b. ok is false when no terminator
// exists; the whole input is then returned as the string.
func cstr(b []byte) (s string, rest []byte, ok bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return string(b), nil, false
}

func be16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

// fit returns the first candidate reply that is no larger than the request,
// or nil. UDP responders use it so they can never amplify traffic.
func fit(req []byte, candidates ...[]byte) []byte {
	for _, c := range candidates {
		if len(c) > 0 && len(c) <= len(req) {
			return c
		}
	}
	return nil
}
