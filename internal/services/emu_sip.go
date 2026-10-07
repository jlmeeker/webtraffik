package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ── SIP ───────────────────────────────────────────────────────────────────────

const (
	sipMaxHead     = 8192 // header block, bytes
	sipMaxHeaders  = 64
	sipMaxBody     = 4096
	sipMaxMessages = 4 // per TCP connection
	sipServer      = "Asterisk PBX 18.12.1"
)

// compact header forms (RFC 3261 §7.3.3)
var sipCompact = map[string]string{"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type"}

type sipMsg struct {
	Method     string
	URI        string
	IsResponse bool
	H          map[string]string // lower-case name -> first value
}

var sipMethodRe = regexp.MustCompile(`^[A-Z]{2,16}$`)

// parseSIP decodes a SIP message's start line and headers. Anything after the
// blank line (the body) is ignored. Sizes are bounded: at most sipMaxHead
// bytes and sipMaxHeaders header lines are examined.
func parseSIP(b []byte) (sipMsg, error) {
	m := sipMsg{H: map[string]string{}}
	if len(b) > sipMaxHead {
		b = b[:sipMaxHead]
	}
	lines := strings.Split(string(b), "\n")
	i := 0
	for i < len(lines) && strings.TrimRight(lines[i], "\r") == "" && i < 8 {
		i++ // tolerate leading CRLF keep-alives
	}
	if i >= len(lines) {
		return m, errors.New("empty message")
	}
	start := strings.TrimRight(lines[i], "\r")
	i++
	f := strings.Fields(start)
	switch {
	case len(f) >= 2 && strings.HasPrefix(f[0], "SIP/"):
		m.IsResponse = true
		m.Method = "RESPONSE"
		m.URI = cleanStr(strings.Join(f[1:], " "), 128)
	case len(f) == 3 && strings.HasPrefix(f[2], "SIP/") && sipMethodRe.MatchString(strings.ToUpper(f[0])):
		m.Method = strings.ToUpper(f[0])
		m.URI = cleanStr(f[1], 200)
	default:
		return m, errors.New("not a SIP start line")
	}
	for n := 0; i < len(lines) && n < sipMaxHeaders; i++ {
		l := strings.TrimRight(lines[i], "\r")
		if l == "" {
			break
		}
		n++
		if l[0] == ' ' || l[0] == '\t' { // folded continuation: ignore
			continue
		}
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if full, ok := sipCompact[name]; ok {
			name = full
		}
		if _, dup := m.H[name]; !dup {
			m.H[name] = cleanStr(strings.TrimSpace(val), 512)
		}
	}
	return m, nil
}

var (
	sipUserRe = regexp.MustCompile(`(?i)username="([^"]{0,64})"`)
	sipRespRe = regexp.MustCompile(`(?i)response="([0-9a-f]{1,128})"`)
)

// sipResponse builds a reply for m. Compact replies drop the optional headers
// so that UDP answers can fit within the request's size.
func sipResponse(m sipMsg, code int, reason string, challenge, compact bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", code, reason)
	for _, h := range [][2]string{{"via", "Via"}, {"from", "From"}, {"to", "To"}, {"call-id", "Call-ID"}, {"cseq", "CSeq"}} {
		v := m.H[h[0]]
		if v == "" {
			continue
		}
		if h[0] == "to" && !strings.Contains(strings.ToLower(v), ";tag=") {
			v += ";tag=" + randHex(3)
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h[1], v)
	}
	if challenge {
		if compact {
			fmt.Fprintf(&b, "WWW-Authenticate: Digest realm=\"sip\",nonce=\"%s\"\r\n", randHex(8))
		} else {
			fmt.Fprintf(&b, "WWW-Authenticate: Digest algorithm=MD5, realm=\"asterisk\", nonce=\"%s\"\r\n", randHex(16))
		}
	}
	if !compact {
		if m.Method == "OPTIONS" {
			b.WriteString("Allow: OPTIONS, REGISTER, INVITE, ACK, BYE, CANCEL\r\n")
		}
		fmt.Fprintf(&b, "Server: %s\r\n", sipServer)
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return []byte(b.String())
}

// sipReplies returns the full and compact replies for m; both nil when no
// reply is due.
func sipReplies(m sipMsg) (full, compact []byte) {
	var code int
	var reason string
	var challenge bool
	switch m.Method {
	case "RESPONSE", "ACK":
		return nil, nil
	case "OPTIONS":
		code, reason = 200, "OK"
	case "REGISTER", "INVITE":
		code, reason, challenge = 401, "Unauthorized", true
	default:
		code, reason = 405, "Method Not Allowed"
	}
	return sipResponse(m, code, reason, challenge, false), sipResponse(m, code, reason, challenge, true)
}

// sipResult turns a parsed message into capture metadata and tags.
func sipResult(m sipMsg, raw []byte) Result {
	ua := m.H["user-agent"]
	meta := map[string]string{"sip_method": m.Method}
	if m.URI != "" {
		meta["sip_uri"] = m.URI
	}
	if ua != "" {
		meta["user_agent"] = cleanStr(ua, 200)
	}
	if v := m.H["from"]; v != "" {
		meta["from"] = cleanStr(v, 200)
	}
	var tags []string
	if auth := m.H["authorization"]; auth != "" {
		if sm := sipUserRe.FindStringSubmatch(auth); sm != nil {
			meta["user"] = sm[1]
			tags = userTags(sm[1])
		}
		if sm := sipRespRe.FindStringSubmatch(auth); sm != nil {
			meta["auth_hash_hex"] = sm[1]
			tags = mergeTags(tags, []string{"credential-attempt"})
		}
	}
	tags = mergeTags(tags, Classify(string(raw), ua))
	return Result{Data: raw, Detail: "sip: " + m.Method, Tags: tags, Meta: meta}
}

// sipUDP answers one datagram. OPTIONS gets 200, REGISTER/INVITE a digest
// challenge; the reply is only sent if it is no larger than the request.
func sipUDP(pkt []byte) ([]byte, Result) {
	m, err := parseSIP(pkt)
	if err != nil {
		return nil, Result{Data: pkt, Detail: "sip: unparseable datagram", Tags: Classify(string(pkt), "")}
	}
	full, compact := sipReplies(m)
	return fit(pkt, full, compact), sipResult(m, pkt)
}

// sipReadHead reads one header block, bounded in line length, line count and
// total size. It returns nil on a clean EOF before any content.
func sipReadHead(br *bufio.Reader) ([]byte, error) {
	var head []byte
	blank := 0
	for lines := 0; lines <= sipMaxHeaders+1; lines++ {
		line, err := br.ReadSlice('\n')
		if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
			if errors.Is(err, bufio.ErrBufferFull) {
				err = errPacketTooLarge
			}
			return head, err
		}
		if len(head)+len(line) > sipMaxHead {
			return head, errPacketTooLarge
		}
		if strings.TrimRight(string(line), "\r\n") == "" {
			if len(head) == 0 {
				if blank++; blank > 8 {
					return nil, errPacketTooLarge
				}
				continue // keep-alive CRLF before a message
			}
			return head, nil
		}
		head = append(head, line...)
		if err != nil {
			return head, err
		}
	}
	return head, errPacketTooLarge
}

// sipTCPHandler serves up to sipMaxMessages requests on a connection.
func sipTCPHandler(_ context.Context, c net.Conn, _ string) Result {
	raw := &rawBuf{}
	br := bufio.NewReaderSize(c, 4096)
	var first *Result
	var methods []string
	for i := 0; i < sipMaxMessages; i++ {
		c.SetReadDeadline(timeIn(emuReadTimeout))
		head, err := sipReadHead(br)
		raw.add(head)
		if len(head) > 0 {
			m, perr := parseSIP(head)
			if perr == nil {
				methods = append(methods, m.Method)
				if first == nil {
					r := sipResult(m, nil)
					first = &r
				}
				if full, _ := sipReplies(m); full != nil {
					writeAll(c, full)
				}
				if cl, _ := strconv.Atoi(m.H["content-length"]); cl > sipMaxBody {
					break
				} else if cl > 0 {
					body := make([]byte, cl)
					n, _ := io.ReadFull(br, body)
					raw.add(body[:n])
				}
			}
		}
		if err != nil {
			break
		}
	}
	if first == nil {
		return Result{Data: raw.b, Detail: "sip: connection, no valid request", Tags: Classify(string(raw.b), "")}
	}
	first.Data = raw.b
	first.Detail = "sip: " + strings.Join(methods, ", ")
	first.Tags = mergeTags(first.Tags, Classify(string(raw.b), first.Meta["user_agent"]))
	return *first
}
