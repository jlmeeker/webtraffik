package intel

import "strings"

// Known internet-measurement operators. Matching is by AS organisation or by a
// reverse-DNS suffix; rDNS matches are only trusted when forward-confirmed
// (see Resolver), so a spoofed PTR record cannot impersonate a scanner.
type scannerDef struct {
	name     string
	asnOrg   []string // lower-case substrings of the AS organisation
	rdnsSufx []string // lower-case domain suffixes (with leading dot)
}

var knownScanners = []scannerDef{
	{"Shodan", []string{"shodan"}, []string{".shodan.io"}},
	{"Censys", []string{"censys"}, []string{".censys-scanner.com", ".censys.io"}},
	{"Shadowserver", []string{"shadowserver"}, []string{".shadowserver.org"}},
	{"Palo Alto Expanse", []string{"palo alto networks", "expanse"}, []string{".expanse.co", ".paloaltonetworks.com"}},
	{"BinaryEdge", []string{"binaryedge"}, []string{".binaryedge.ninja", ".binaryedge.io"}},
	{"Stretchoid", []string{"stretchoid"}, []string{".stretchoid.com"}},
	{"Internet Census Group", []string{"internet census"}, []string{".internet-census.org"}},
	{"Recyber", []string{"recyber"}, []string{".recyber.net"}},
	{"Onyphe", []string{"onyphe"}, []string{".onyphe.io"}},
	{"LeakIX", []string{"leakix"}, []string{".leakix.net"}},
	{"Netlas", []string{"netlas"}, []string{".netlas.io"}},
	{"Driftnet", []string{"driftnet"}, []string{".driftnet.io"}},
	{"University of Michigan", nil, []string{".umich.edu"}},
	{"Rapid7 Sonar", []string{"rapid7"}, []string{".rapid7.com", ".sonar.rapid7.com"}},
	{"Alpha Strike Labs", []string{"alphastrike"}, []string{".alphastrike.io"}},
	{"CriminalIP", []string{"criminalip", "ai spera"}, []string{".criminalip.com"}},
	{"Quadmetrics", nil, []string{".quadmetrics.com"}},
}

// MatchASNOrg returns the known scanner operator for an AS organisation.
func MatchASNOrg(org string) string {
	l := strings.ToLower(org)
	if l == "" {
		return ""
	}
	for _, s := range knownScanners {
		for _, sub := range s.asnOrg {
			if strings.Contains(l, sub) {
				return s.name
			}
		}
	}
	return ""
}

// MatchRDNS returns the known scanner operator for a reverse-DNS name.
func MatchRDNS(host string) string {
	h := "." + strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range knownScanners {
		for _, suf := range s.rdnsSufx {
			if strings.HasSuffix(h, suf) {
				return s.name
			}
		}
	}
	return ""
}
