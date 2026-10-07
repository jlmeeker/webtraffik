// Package intel turns raw captures into intelligence: how much a connection
// revealed (kind), what the source appears to be doing (class), whether it is
// a known research scanner, and which events belong to the same campaign.
package intel

import (
	"crypto/sha1"
	"encoding/hex"

	"webtraffik/internal/event"
)

// exploitTags are classifier labels that indicate an attack payload rather
// than reconnaissance (see services/classify.go).
var exploitTags = map[string]bool{
	"log4shell": true, "path-traversal": true, "shell-injection": true, "sqli": true,
	"xss": true, "php-rce": true, "router-exploit": true, "spring4shell": true,
	"struts-ognl": true, "redis-exploit": true, "mirai-like": true,
	"amplification-probe": true,
}

// researchTags mark crawlers that identify themselves as measurement projects.
var researchTags = map[string]bool{
	"scanner:censys": true, "scanner:shodan": true, "scanner:expanse": true,
	"scanner:internet-measurement": true,
}

// Annotate fills Kind and Class on ev. A Kind already set by the capture
// source (XDP-only observations) is kept.
func Annotate(ev *event.ConnectionEvent) {
	if ev.Kind == "" {
		ev.Kind = kindOf(ev)
	}
	ev.Class = classOf(ev)
	ev.FP = Fingerprints(ev)
}

func kindOf(ev *event.ConnectionEvent) string {
	for _, t := range ev.Tags {
		if t == "connect-only" {
			return event.KindProbe
		}
	}
	if ev.ClientData == "" && len(ev.Meta) == 0 && len(ev.Tags) == 0 {
		return event.KindProbe
	}
	return event.KindSession
}

func classOf(ev *event.ConnectionEvent) string {
	research := ev.Scanner != ""
	for _, t := range ev.Tags {
		if exploitTags[t] {
			return event.ClassExploit
		}
		if researchTags[t] {
			research = true
		}
	}
	if ev.Meta["secret"] != "" || ev.Meta["auth_hash_hex"] != "" || ev.Meta["attempts"] != "" {
		return event.ClassBruteforce
	}
	for _, t := range ev.Tags {
		if t == "mirai-default-creds" || t == "privileged-user" {
			return event.ClassBruteforce
		}
	}
	if research {
		return event.ClassResearch
	}
	if ev.Kind == event.KindSession || ev.Kind == event.KindProbe || ev.Kind == event.KindObserved {
		return event.ClassScan
	}
	return event.ClassUnknown
}

// Fingerprints returns the campaign fingerprints of an event: TLS client
// hashes and the hash of an attack or binary payload. Generic text requests
// ("GET / HTTP/1.1") are deliberately excluded or every scanner would merge.
func Fingerprints(ev *event.ConnectionEvent) []string {
	var fp []string
	if v := ev.Meta["ja4"]; v != "" {
		fp = append(fp, "ja4:"+v)
	}
	if v := ev.Meta["ja3"]; v != "" {
		fp = append(fp, "ja3:"+v)
	}
	if h := payloadHash(ev); h != "" {
		fp = append(fp, "pl:"+h)
	}
	return fp
}

// payloadHash hashes the first bytes of the client payload when it is an
// exploit or mostly binary, so identical attack kits cluster together.
func payloadHash(ev *event.ConnectionEvent) string {
	if len(ev.ClientData) < 48 { // hex: at least 24 bytes
		return ""
	}
	raw, err := hex.DecodeString(ev.ClientData[:min(len(ev.ClientData), 256)])
	if err != nil || len(raw) < 24 {
		return ""
	}
	exploit := false
	for _, t := range ev.Tags {
		if exploitTags[t] {
			exploit = true
		}
	}
	nonPrint := 0
	for _, b := range raw {
		if b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e {
			nonPrint++
		}
	}
	if !exploit && nonPrint*4 < len(raw) {
		return ""
	}
	if isTLSHello(raw) { // covered by ja3/ja4; the hello embeds a random
		return ""
	}
	sum := sha1.Sum(raw[:min(len(raw), 64)])
	return hex.EncodeToString(sum[:6])
}

func isTLSHello(b []byte) bool { return len(b) > 5 && b[0] == 0x16 && b[1] == 0x03 }
