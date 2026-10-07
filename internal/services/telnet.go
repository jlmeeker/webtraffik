package services

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// readLine reads one CR/LF-terminated line of at most max bytes, discarding
// Telnet IAC negotiation sequences.
func readTelnetLine(br *bufio.Reader, max int) (string, error) {
	var out []byte
	for len(out) < max {
		b, err := br.ReadByte()
		if err != nil {
			return string(out), err
		}
		switch b {
		case 0xff: // IAC: skip command + option (or subnegotiation)
			cmd, err := br.ReadByte()
			if err != nil {
				return string(out), err
			}
			if cmd == 0xfa { // SB ... IAC SE
				for {
					x, err := br.ReadByte()
					if err != nil {
						return string(out), err
					}
					if x == 0xff {
						if y, _ := br.ReadByte(); y == 0xf0 {
							break
						}
					}
				}
			} else if cmd >= 0xfb && cmd <= 0xfe {
				if _, err := br.ReadByte(); err != nil {
					return string(out), err
				}
			}
		case '\n':
			return strings.TrimRight(string(out), "\r\x00"), nil
		default:
			out = append(out, b)
		}
	}
	return string(out), nil
}

// telnetHandler emulates a BusyBox-style login prompt and records up to three
// credential attempts, as Mirai-family bots and brute-forcers send them.
func telnetHandler(ctx context.Context, c net.Conn, srcIP string) Result {
	br := bufio.NewReader(c)
	// IAC DO TERMINAL-TYPE, IAC DO NAWS, IAC WILL ECHO
	c.Write([]byte("\xff\xfd\x18\xff\xfd\x1f\xff\xfb\x01"))

	type cred struct{ user, pass string }
	var creds []cred
	for i := 0; i < 3; i++ {
		c.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := c.Write([]byte("\r\nlogin: ")); err != nil {
			break
		}
		user, err := readTelnetLine(br, 128)
		if err != nil && user == "" {
			break
		}
		c.Write([]byte("Password: "))
		pass, err2 := readTelnetLine(br, 128)
		creds = append(creds, cred{user, pass})
		if err2 != nil && pass == "" {
			break
		}
		time.Sleep(time.Second) // real login pauses before refusing
		c.Write([]byte("\r\nLogin incorrect\r\n"))
	}

	res := Result{Meta: map[string]string{}, Detail: "telnet connection, no login attempted"}
	if len(creds) == 0 {
		return res
	}
	res.Meta["user"], res.Meta["secret"] = creds[0].user, creds[0].pass
	res.Meta["attempts"] = fmt.Sprint(len(creds))
	var parts []string
	var tags []string
	for _, cr := range creds {
		parts = append(parts, cr.user+":"+cr.pass)
		tags = append(tags, ClassifyCreds(cr.user, cr.pass)...)
	}
	res.Detail = "telnet login " + strings.Join(parts, ", ")
	res.Tags = mergeTags(tags, []string{"credential-attempt"})
	return res
}
