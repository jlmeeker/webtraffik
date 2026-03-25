package ebpf

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// DefaultInterface returns the name of the network interface associated with
// the default IPv4 route, by parsing /proc/net/route.
//
// It reads the kernel's routing table directly rather than shelling out to
// `ip route` or `route`, keeping the implementation dependency-free and
// compatible with minimal container environments.
//
// Returns an error if /proc/net/route is unavailable (non-Linux) or if no
// default route is found.
func DefaultInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("ebpf: read /proc/net/route: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	// Line 0 is the header; entries start at line 1.
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Field 1 is the destination in hex; "00000000" is 0.0.0.0 (default route).
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("ebpf: no default route found in /proc/net/route")
}

// InterfaceIndex returns the OS index for the named interface.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("ebpf: interface %q: %w", name, err)
	}
	return iface.Index, nil
}
