package services

import (
	"crypto/tls"
	"io"
	"net"
	"regexp"
	"testing"
	"time"
)

// captureClientHello makes a real crypto/tls client write its ClientHello and
// returns the raw first record.
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	go func() {
		c := tls.Client(cli, cfg)
		c.Handshake() // fails once we close; we only need the hello
	}()
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	return append(hdr, body...)
}

func TestParseClientHello(t *testing.T) {
	rec := captureClientHello(t, &tls.Config{
		ServerName: "example.com", InsecureSkipVerify: true,
		NextProtos: []string{"h2", "http/1.1"},
	})
	fp, err := parseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if fp.SNI != "example.com" {
		t.Errorf("SNI = %q", fp.SNI)
	}
	if len(fp.Ciphers) == 0 || len(fp.Extensions) == 0 {
		t.Errorf("empty ciphers/extensions: %+v", fp)
	}
	if fp.Version != tls.VersionTLS13 {
		t.Errorf("Version = %#x, want TLS1.3", fp.Version)
	}
	if len(fp.ALPN) != 2 || fp.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v", fp.ALPN)
	}
	if len(fp.JA3Hash) != 32 {
		t.Errorf("JA3Hash = %q", fp.JA3Hash)
	}
	// JA4 shape: t13d<2-digit ciphers><2-digit exts>h1_<12hex>_<12hex>.
	if !regexp.MustCompile(`^t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(fp.JA4) {
		t.Errorf("JA4 = %q has wrong shape", fp.JA4)
	}
	// Same client config => same fingerprint (hash is order-stable).
	rec2 := captureClientHello(t, &tls.Config{
		ServerName: "other.test", InsecureSkipVerify: true,
		NextProtos: []string{"h2", "http/1.1"},
	})
	fp2, _ := parseClientHello(rec2)
	if fp2.JA3Hash == "" || fp2.JA4[len(fp2.JA4)-12:] != fp.JA4[len(fp.JA4)-12:] {
		// extension hash excludes SNI so it must match across server names
		t.Errorf("JA4 ext hash changed with SNI: %q vs %q", fp.JA4, fp2.JA4)
	}
}

func TestParseClientHelloGarbage(t *testing.T) {
	for _, in := range [][]byte{
		nil, []byte("GET / HTTP/1.1\r\n\r\n"), {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0},
		{0x16, 0x03, 0x01, 0xff, 0xff, 0x01},
	} {
		if _, err := parseClientHello(in); err == nil {
			t.Errorf("parseClientHello(%q) should fail", in)
		}
	}
}

func TestGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xdada, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x1301, 0x0a1a, 0xc02b} {
		if isGREASE(v) {
			t.Errorf("%#x should not be GREASE", v)
		}
	}
}
