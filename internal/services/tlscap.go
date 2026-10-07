package services

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── ClientHello fingerprinting ────────────────────────────────────────────────

// tlsFingerprint is what we learn from a TLS ClientHello.
type tlsFingerprint struct {
	LegacyVersion uint16
	Version       uint16 // highest of supported_versions, else LegacyVersion
	Ciphers       []uint16
	Extensions    []uint16
	Curves        []uint16
	PointFormats  []uint8
	SigAlgs       []uint16
	ALPN          []string
	SNI           string
	JA3           string
	JA3Hash       string
	JA4           string
}

func (f *tlsFingerprint) meta() map[string]string {
	m := map[string]string{"ja3": f.JA3Hash, "ja4": f.JA4}
	if f.SNI != "" {
		m["sni"] = f.SNI
	}
	return m
}

// isGREASE reports whether v is a GREASE placeholder (RFC 8701).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

var errNotClientHello = errors.New("not a TLS ClientHello")

// parseClientHello parses the first TLS record of a connection. rec must start
// with the 5-byte record header.
func parseClientHello(rec []byte) (*tlsFingerprint, error) {
	if len(rec) < 9 || rec[0] != 0x16 || rec[1] != 0x03 {
		return nil, errNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	if len(rec) < 5+recLen {
		return nil, errNotClientHello
	}
	hs := rec[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, errNotClientHello
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil, errNotClientHello
	}
	b := hs[4 : 4+hsLen]

	r := &reader{b: b}
	f := &tlsFingerprint{}
	f.LegacyVersion = r.u16()
	r.skip(32) // random
	r.skip(int(r.u8()))
	for cs := r.sub(int(r.u16())); cs.len() >= 2; {
		f.Ciphers = append(f.Ciphers, cs.u16())
	}
	r.skip(int(r.u8())) // compression methods
	if r.err {
		return nil, errNotClientHello
	}
	f.Version = f.LegacyVersion
	if r.len() >= 2 {
		exts := r.sub(int(r.u16()))
		for exts.len() >= 4 && !exts.err {
			typ := exts.u16()
			data := exts.sub(int(exts.u16()))
			if exts.err {
				break
			}
			f.Extensions = append(f.Extensions, typ)
			switch typ {
			case 0x0000: // server_name
				data.skip(2)
				if data.u8() == 0 {
					f.SNI = string(data.rest(int(data.u16())))
				}
			case 0x000a: // supported_groups
				for l := data.sub(int(data.u16())); l.len() >= 2; {
					f.Curves = append(f.Curves, l.u16())
				}
			case 0x000b: // ec_point_formats
				for l := data.sub(int(data.u8())); l.len() >= 1; {
					f.PointFormats = append(f.PointFormats, l.u8())
				}
			case 0x000d: // signature_algorithms
				for l := data.sub(int(data.u16())); l.len() >= 2; {
					f.SigAlgs = append(f.SigAlgs, l.u16())
				}
			case 0x0010: // ALPN
				for l := data.sub(int(data.u16())); l.len() >= 1; {
					f.ALPN = append(f.ALPN, string(l.rest(int(l.u8()))))
				}
			case 0x002b: // supported_versions
				for l := data.sub(int(data.u8())); l.len() >= 2; {
					if v := l.u16(); !isGREASE(v) && v > f.Version {
						f.Version = v
					}
				}
			}
		}
	}
	f.computeHashes()
	return f, nil
}

// reader is a tiny bounds-checked big-endian cursor; any overrun sets err and
// returns zeros so parsing never panics on hostile input.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) len() int { return len(r.b) }
func (r *reader) skip(n int) {
	if n < 0 || n > len(r.b) {
		r.err, r.b = true, nil
		return
	}
	r.b = r.b[n:]
}
func (r *reader) rest(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err, r.b = true, nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *reader) sub(n int) *reader { return &reader{b: r.rest(n), err: r.err} }
func (r *reader) u8() uint8 {
	if len(r.b) < 1 {
		r.err = true
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}
func (r *reader) u16() uint16 {
	if len(r.b) < 2 {
		r.err, r.b = true, nil
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func joinU16(vs []uint16, sep string, skipGrease bool) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		if skipGrease && isGREASE(v) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, sep)
}

func hex4(vs []uint16) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if isGREASE(v) {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return out
}

func trunc12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func (f *tlsFingerprint) computeHashes() {
	// JA3: version,ciphers,extensions,curves,point-formats (GREASE removed).
	pf := make([]string, len(f.PointFormats))
	for i, v := range f.PointFormats {
		pf[i] = strconv.Itoa(int(v))
	}
	f.JA3 = strings.Join([]string{
		strconv.Itoa(int(f.LegacyVersion)),
		joinU16(f.Ciphers, "-", true),
		joinU16(f.Extensions, "-", true),
		joinU16(f.Curves, "-", true),
		strings.Join(pf, "-"),
	}, ",")
	sum := md5.Sum([]byte(f.JA3))
	f.JA3Hash = hex.EncodeToString(sum[:])

	// JA4 (FoxIO): a_b_c.
	ver := "00"
	switch f.Version {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	case 0x0300:
		ver = "s3"
	case 0x0002:
		ver = "s2"
	}
	sni := "i"
	if f.SNI != "" {
		sni = "d"
	}
	var nCiphers, nExts int
	for _, c := range f.Ciphers {
		if !isGREASE(c) {
			nCiphers++
		}
	}
	for _, e := range f.Extensions {
		if !isGREASE(e) {
			nExts++
		}
	}
	alpn := "00"
	if len(f.ALPN) > 0 && f.ALPN[0] != "" {
		a := f.ALPN[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, min(nCiphers, 99), min(nExts, 99), alpn)

	ciphers := hex4(f.Ciphers)
	sort.Strings(ciphers)
	b := "000000000000"
	if len(ciphers) > 0 {
		b = trunc12(strings.Join(ciphers, ","))
	}

	var exts []string
	for _, e := range f.Extensions {
		if isGREASE(e) || e == 0x0000 || e == 0x0010 {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", e))
	}
	sort.Strings(exts)
	cs := strings.Join(exts, ",")
	if sa := hex4(f.SigAlgs); len(sa) > 0 {
		cs += "_" + strings.Join(sa, ",")
	}
	c := "000000000000"
	if len(exts) > 0 {
		c = trunc12(cs)
	}
	f.JA4 = a + "_" + b + "_" + c
}

// ── TLS listener ──────────────────────────────────────────────────────────────

// fpConn is a server-side TLS connection that remembers its ClientHello
// fingerprint.
type fpConn struct {
	net.Conn
	fp *tlsFingerprint
}

// peekConn replays bytes already buffered while fingerprinting.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

type tlsListener struct {
	net.Listener
	env  *Env
	port string
	cfg  *tls.Config

	ch    chan net.Conn
	errc  chan error
	done  chan struct{}
	close sync.Once
	err   error
}

func (e *Env) newTLSListener(inner net.Listener, port string) (net.Listener, error) {
	cert, err := loadOrCreateCert(e.DataDir)
	if err != nil {
		return nil, err
	}
	l := &tlsListener{
		Listener: inner, env: e, port: port,
		cfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS10, // accept legacy clients: we want to see them
			NextProtos:   []string{"http/1.1"},
		},
		ch:   make(chan net.Conn),
		errc: make(chan error, 1),
		done: make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

func (l *tlsListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// Transient errors (EMFILE, ECONNABORTED…) must not kill the
			// listener: back off and keep accepting.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() || isTemporary(err) {
				select {
				case <-time.After(50 * time.Millisecond):
					continue
				case <-l.done:
					return
				}
			}
			l.errc <- err
			return
		}
		go l.prepare(c)
	}
}

func (l *tlsListener) Accept() (net.Conn, error) {
	if l.err != nil {
		return nil, l.err
	}
	select {
	case c := <-l.ch:
		return c, nil
	case err := <-l.errc:
		l.err = err
		return nil, err
	}
}

// prepare peeks the ClientHello off the wire without consuming it, then hands
// the connection to crypto/tls. Non-TLS traffic is recorded and dropped.
func (l *tlsListener) prepare(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(c, 5+16384)
	hdr, err := br.Peek(5)
	if err != nil {
		c.Close() // connected and said nothing (or hung up): connect-only
		l.recordConnectOnly(c)
		return
	}
	var fp *tlsFingerprint
	if hdr[0] == 0x16 && hdr[1] == 0x03 {
		n := 5 + int(binary.BigEndian.Uint16(hdr[3:5]))
		if n <= 5+16384 {
			if rec, err := br.Peek(n); err == nil {
				fp, _ = parseClientHello(rec)
			}
		}
	}
	if fp == nil {
		data, _ := br.Peek(min(br.Buffered(), 2048))
		raw := append([]byte(nil), data...)
		cp := Capture{
			SrcIP: extractConnIP(c.RemoteAddr()), DstPort: l.port, Protocol: "tcp",
			Data: raw, Detail: "non-TLS data on TLS port",
			Tags: mergeTags([]string{"non-tls"}, Classify(string(raw), "")),
		}
		c.Close()
		l.env.Capture(cp)
		return
	}
	c.SetReadDeadline(time.Time{})
	select {
	case l.ch <- &fpConn{Conn: tls.Server(&peekConn{Conn: c, r: br}, l.cfg), fp: fp}:
	case <-l.done:
		c.Close() // listener closed while we were fingerprinting
	}
}

// Close stops the listener and releases connections still being fingerprinted.
func (l *tlsListener) Close() error {
	l.close.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// isTemporary reports errors worth retrying (net.Error.Temporary is
// deprecated but is how EMFILE/ENFILE surface from Accept).
func isTemporary(err error) bool {
	var t interface{ Temporary() bool }
	return errors.As(err, &t) && t.Temporary()
}

func (l *tlsListener) recordConnectOnly(c net.Conn) {
	l.env.Capture(Capture{
		SrcIP: extractConnIP(c.RemoteAddr()), DstPort: l.port, Protocol: "tcp",
		Detail: "connection without data", Tags: []string{"connect-only"},
	})
}

// ── Persistent self-signed certificate ────────────────────────────────────────

// loadOrCreateCert returns the honeypot's TLS certificate, generating and
// persisting a self-signed one on first use so the fingerprint is stable
// across restarts.
func loadOrCreateCert(dir string) (tls.Certificate, error) {
	if dir == "" {
		dir = "."
	}
	certPath := filepath.Join(dir, "tls_cert.pem")
	keyPath := filepath.Join(dir, "tls_key.pem")
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"Internet Widgits Pty Ltd"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// Persistence is best-effort (read-only dir => ephemeral cert).
	if err := os.WriteFile(certPath, certPEM, 0o644); err == nil {
		_ = os.WriteFile(keyPath, keyPEM, 0o600)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
