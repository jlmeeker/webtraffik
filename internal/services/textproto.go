package services

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxSessionLines = 24
	maxLineBytes    = 1024
)

// session accumulates what a text-protocol conversation revealed.
type session struct {
	cmds  []string          // commands seen, in order (capped)
	raw   []byte            // raw client bytes
	creds [][2]string       // user, secret
	meta  map[string]string // extras
}

func (s *session) note(cmd string) {
	if len(s.cmds) < maxSessionLines {
		s.cmds = append(s.cmds, truncate(cmd, 160))
	}
}

func (s *session) result(proto string) Result {
	res := Result{Data: clip(s.raw, maxClientData), Meta: s.meta}
	if res.Meta == nil {
		res.Meta = map[string]string{}
	}
	var tags []string
	if len(s.creds) > 0 {
		res.Meta["user"], res.Meta["secret"] = s.creds[0][0], s.creds[0][1]
		tags = append(tags, "credential-attempt")
		for _, c := range s.creds {
			tags = append(tags, ClassifyCreds(c[0], c[1])...)
		}
	}
	if len(s.cmds) > 0 {
		res.Detail = proto + ": " + truncate(strings.Join(s.cmds, " ; "), 300)
	} else {
		res.Detail = proto + " connection, no commands"
	}
	tags = append(tags, Classify(strings.Join(s.cmds, "\n"), "")...)
	res.Tags = mergeTags(tags)
	return res
}

// lineProto drives a request/response text protocol. handle returns the reply
// to write (may be empty) and whether to close afterwards.
func lineProto(c net.Conn, banner string, proto string, handle func(line string, s *session) (reply string, quit bool)) Result {
	s := &session{meta: map[string]string{}}
	br := bufio.NewReaderSize(io.LimitReader(c, 16<<10), 4096)
	if banner != "" {
		c.Write([]byte(banner))
	}
	for i := 0; i < maxSessionLines; i++ {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		if len(line) > maxLineBytes {
			line = line[:maxLineBytes]
		}
		if line != "" {
			s.raw = append(s.raw, line...)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" {
			reply, quit := handle(trimmed, s)
			if reply != "" {
				c.Write([]byte(reply))
			}
			if quit {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return s.result(proto)
}

func splitCmd(line string) (cmd, arg string) {
	cmd, arg, _ = strings.Cut(strings.TrimSpace(line), " ")
	return strings.ToUpper(cmd), strings.TrimSpace(arg)
}

// ── FTP ───────────────────────────────────────────────────────────────────────

func ftpHandler(_ context.Context, c net.Conn, _ string) Result {
	var user string
	return lineProto(c, "220 FTP Server ready.\r\n", "ftp", func(line string, s *session) (string, bool) {
		cmd, arg := splitCmd(line)
		switch cmd {
		case "USER":
			user = arg
			s.note("USER " + arg)
			return "331 Please specify the password.\r\n", false
		case "PASS":
			s.note("PASS ***")
			s.creds = append(s.creds, [2]string{user, arg})
			return "530 Login incorrect.\r\n", false
		case "QUIT":
			s.note("QUIT")
			return "221 Goodbye.\r\n", true
		case "SYST":
			s.note("SYST")
			return "215 UNIX Type: L8\r\n", false
		case "FEAT":
			s.note("FEAT")
			return "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n", false
		case "AUTH":
			s.note(line)
			return "530 Please login with USER and PASS.\r\n", false
		default:
			s.note(line)
			return "530 Please login with USER and PASS.\r\n", false
		}
	})
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

func smtpHandler(_ context.Context, c net.Conn, _ string) Result {
	const host = "mail.example.com"
	var authStage int // 0 none, 1 expecting user, 2 expecting password
	var authUser string
	dec := func(s string) string {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return s
		}
		return string(b)
	}
	return lineProto(c, "220 "+host+" ESMTP Postfix (Ubuntu)\r\n", "smtp", func(line string, s *session) (string, bool) {
		switch authStage {
		case 1:
			authUser = dec(line)
			authStage = 2
			return "334 UGFzc3dvcmQ6\r\n", false
		case 2:
			s.creds = append(s.creds, [2]string{authUser, dec(line)})
			s.note("AUTH LOGIN " + authUser)
			authStage = 0
			return "535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n", false
		}
		cmd, arg := splitCmd(line)
		switch cmd {
		case "EHLO", "HELO":
			s.note(cmd + " " + arg)
			return "250-" + host + "\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n", false
		case "AUTH":
			mech, rest := splitCmd(arg)
			switch mech {
			case "PLAIN":
				if rest != "" {
					parts := strings.Split(dec(rest), "\x00")
					if len(parts) == 3 {
						s.creds = append(s.creds, [2]string{parts[1], parts[2]})
						s.note("AUTH PLAIN " + parts[1])
					}
					return "535 5.7.8 Error: authentication failed: \r\n", false
				}
				return "334 \r\n", false
			case "LOGIN":
				authStage = 1
				return "334 VXNlcm5hbWU6\r\n", false
			}
			s.note(line)
			return "504 5.5.4 Unrecognized authentication type\r\n", false
		case "MAIL":
			s.note(line)
			return "250 2.1.0 Ok\r\n", false
		case "RCPT":
			s.note(line)
			return "554 5.7.1 <" + "relay" + ">: Relay access denied\r\n", false
		case "STARTTLS":
			s.note("STARTTLS")
			return "454 4.7.0 TLS not available due to local problem\r\n", false
		case "VRFY", "EXPN":
			s.note(line)
			return "252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery\r\n", false
		case "RSET", "NOOP":
			return "250 2.0.0 Ok\r\n", false
		case "QUIT":
			s.note("QUIT")
			return "221 2.0.0 Bye\r\n", true
		default:
			s.note(line)
			return "502 5.5.2 Error: command not recognized\r\n", false
		}
	})
}

// ── POP3 ──────────────────────────────────────────────────────────────────────

func pop3Handler(_ context.Context, c net.Conn, _ string) Result {
	var user string
	return lineProto(c, "+OK POP3 server ready\r\n", "pop3", func(line string, s *session) (string, bool) {
		cmd, arg := splitCmd(line)
		switch cmd {
		case "USER":
			user = arg
			s.note("USER " + arg)
			return "+OK\r\n", false
		case "PASS":
			s.note("PASS ***")
			s.creds = append(s.creds, [2]string{user, arg})
			return "-ERR [AUTH] Authentication failed.\r\n", false
		case "CAPA":
			return "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\n.\r\n", false
		case "QUIT":
			s.note("QUIT")
			return "+OK Logging out\r\n", true
		default:
			s.note(line)
			return "-ERR Unknown command\r\n", false
		}
	})
}

// ── Redis ─────────────────────────────────────────────────────────────────────

// redisHandler parses RESP arrays and inline commands. It refuses everything
// with NOAUTH (like a password-protected instance) but records the commands,
// which is where the interesting exploitation attempts (CONFIG SET dir,
// SLAVEOF, MODULE LOAD) show up.
func redisHandler(_ context.Context, c net.Conn, _ string) Result {
	s := &session{meta: map[string]string{}}
	br := bufio.NewReaderSize(io.LimitReader(c, 32<<10), 4096)
	for i := 0; i < maxSessionLines; i++ {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		args, raw, err := readRESPCommand(br)
		s.raw = append(s.raw, raw...)
		if len(args) > 0 {
			name := strings.ToUpper(args[0])
			s.note(strings.Join(args, " "))
			switch name {
			case "PING":
				c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			case "AUTH":
				if len(args) >= 2 {
					user := "default"
					pass := args[len(args)-1]
					if len(args) >= 3 {
						user = args[1]
					}
					s.creds = append(s.creds, [2]string{user, pass})
				}
				c.Write([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n"))
			case "QUIT":
				c.Write([]byte("+OK\r\n"))
				return s.result("redis")
			default:
				c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			}
		}
		if err != nil {
			break
		}
	}
	return s.result("redis")
}

// readRESPCommand reads one command in RESP array or inline form.
func readRESPCommand(br *bufio.Reader) (args []string, raw []byte, err error) {
	line, err := br.ReadString('\n')
	raw = append(raw, line...)
	if err != nil && line == "" {
		return nil, raw, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), raw, err // inline command
	}
	n, convErr := strconv.Atoi(line[1:])
	if convErr != nil || n < 0 || n > 64 {
		return nil, raw, fmt.Errorf("bad RESP array header")
	}
	for i := 0; i < n; i++ {
		hdr, err := br.ReadString('\n')
		raw = append(raw, hdr...)
		if err != nil {
			return args, raw, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		if !strings.HasPrefix(hdr, "$") {
			return args, raw, fmt.Errorf("bad RESP bulk header")
		}
		l, convErr := strconv.Atoi(hdr[1:])
		if convErr != nil || l < 0 || l > 4096 {
			return args, raw, fmt.Errorf("bad RESP bulk length")
		}
		buf := make([]byte, l+2)
		if n, err := io.ReadFull(br, buf); err != nil {
			raw = append(raw, buf[:n]...)
			return args, raw, err
		}
		raw = append(raw, buf...)
		args = append(args, string(buf[:l]))
	}
	return args, raw, nil
}
