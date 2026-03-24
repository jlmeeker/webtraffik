// Package traceroute runs a traceroute/tracepath to a target IP and emits
// hops incrementally so callers can stream them to clients as they arrive.
//
// It tries the following tools in order until one succeeds:
//  1. traceroute  (most systems, requires net_raw or setuid)
//  2. tracepath   (Linux fallback, no special privileges needed)
//
// Unresponsive hops (represented as "* * *" or "???") are silently skipped.
// Each hop that has a resolvable public IP is emitted on the provided channel.
package traceroute

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// Hop represents a single traceroute hop that has a valid public IP address.
type Hop struct {
	// N is the hop number (1-based).
	N int `json:"n"`
	// IP is the router/gateway IP at this hop.
	IP string `json:"ip"`
	// Lat/Lon is the geolocation of this hop (0,0 if unknown).
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
	// City and CountryCode are optional labels for display.
	City        string `json:"city"`
	CountryCode string `json:"cc"`
}

// GeoFunc is the signature of a geo lookup callback (matches geo.GeoLocator.Lookup).
type GeoFunc func(ip string) (lat, lon float64, city, cc string)

// reIPv4 matches a dotted-decimal IPv4 address (non-capturing context).
var reIPv4 = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

// reIPv6 matches a bare IPv6 address that appears inside parentheses in
// traceroute / tracepath output, e.g.  "2001:db8::1" or "(2001:db8::1)".
var reIPv6 = regexp.MustCompile(`\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b`)

// isPrivate returns true for RFC-1918 / link-local / loopback addresses that
// are not useful to geolocate.
func isPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsUnspecified()
}

// extractIP returns the first public IP found in a traceroute output line, or
// an empty string if none is found.
func extractIP(line string) string {
	// Prefer IPv4 — traceroute/tracepath always shows it when available
	if m := reIPv4.FindStringSubmatch(line); m != nil {
		ip := m[1]
		if !isPrivate(ip) {
			return ip
		}
	}
	// IPv6 fallback — only match lines with parenthesised addresses
	if strings.ContainsAny(line, "()") {
		if m := reIPv6.FindStringSubmatch(line); m != nil {
			ip := m[1]
			if !isPrivate(ip) {
				return ip
			}
		}
	}
	return ""
}

// Run executes a traceroute to target and sends each resolved hop to ch.
// The channel is closed when the traceroute finishes or ctx is cancelled.
// geo is called for every hop IP to obtain lat/lon/city/cc; passing nil
// disables geolocation (hops are emitted with zero coordinates).
//
// maxHops caps the traceroute depth (sensible default: 20).
func Run(ctx context.Context, target string, maxHops int, geo GeoFunc, ch chan<- Hop) {
	defer close(ch)

	if maxHops <= 0 {
		maxHops = 20
	}

	cmd, args := buildCmd(target, maxHops)
	if cmd == "" {
		log.Printf("traceroute: no suitable tool found (tried traceroute, tracepath)")
		return
	}

	c := exec.CommandContext(ctx, cmd, args...)
	out, err := c.StdoutPipe()
	if err != nil {
		log.Printf("traceroute: stdout pipe: %v", err)
		return
	}
	c.Stderr = nil // discard stderr

	if err := c.Start(); err != nil {
		log.Printf("traceroute: start %q: %v", cmd, err)
		return
	}

	scanner := bufio.NewScanner(out)
	hopNum := 0
	seenIPs := make(map[string]bool) // de-duplicate IPs across hops

	for scanner.Scan() {
		line := scanner.Text()

		// Extract hop number from the beginning of the line (optional — some
		// tools print it, others don't).  We fall back to an incrementing counter.
		n := parseHopNumber(line)
		if n > 0 {
			hopNum = n
		} else {
			hopNum++
		}

		ip := extractIP(line)
		if ip == "" || seenIPs[ip] {
			continue
		}
		seenIPs[ip] = true

		hop := Hop{N: hopNum, IP: ip}
		if geo != nil {
			hop.Lat, hop.Lon, hop.City, hop.CountryCode = geo(ip)
		}
		// Only emit hops that have valid coordinates (or were explicitly
		// requested without geo — caller decides what to do with 0,0).
		select {
		case ch <- hop:
		case <-ctx.Done():
			_ = c.Process.Kill()
			return
		}
	}

	_ = c.Wait()
}

// reHopNumber matches a leading hop number in a traceroute line, e.g. " 1 " or "1  ".
var reHopNumber = regexp.MustCompile(`^\s*(\d+)\s`)

func parseHopNumber(line string) int {
	m := reHopNumber.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	n := 0
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

// buildCmd returns the command and arguments to run, trying traceroute first
// then tracepath.  Returns ("", nil) if neither is available.
func buildCmd(target string, maxHops int) (string, []string) {
	maxHopsStr := fmt.Sprintf("%d", maxHops)

	if path, err := exec.LookPath("traceroute"); err == nil {
		return path, []string{
			"-n",             // numeric — no DNS reverse lookups (faster)
			"-m", maxHopsStr, // max hops
			"-w", "1", // 1-second timeout per probe
			"-q", "1", // 1 probe per hop (faster, good enough for path)
			target,
		}
	}

	if path, err := exec.LookPath("tracepath"); err == nil {
		// tracepath does not support -q or -w; -n is the only useful flag here
		return path, []string{
			"-n",
			"-m", maxHopsStr,
			target,
		}
	}

	return "", nil
}
