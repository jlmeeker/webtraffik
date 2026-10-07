// Package event defines the ConnectionEvent shared by the capture pipeline,
// the database, the metrics cache and the dashboard API.
package event

import "strings"

// ConnectionEvent is sent to the browser over WebSocket and persisted to SQLite.
//
// Fields added after the original schema are all optional in JSON
// (omitempty) so older frontends keep working.
type ConnectionEvent struct {
	ID         int64             `json:"id,omitempty"` // database row id; 0 for live events not yet stored
	Time       string            `json:"time"`
	SrcIP      string            `json:"src_ip"`
	DstIP      string            `json:"dst_ip"`
	DstPort    string            `json:"dst_port"`
	Protocol   string            `json:"protocol"` // "tcp", "udp" or "icmp"
	SrcLat     float64           `json:"src_lat"`
	SrcLon     float64           `json:"src_lon"`
	DstLat     float64           `json:"dst_lat"`
	DstLon     float64           `json:"dst_lon"`
	SrcCity    string            `json:"src_city"`
	DstCity    string            `json:"dst_city"`
	SrcCC      string            `json:"src_cc"`
	DstCC      string            `json:"dst_cc"`
	ASN        uint32            `json:"asn,omitempty"`         // source autonomous system number
	ASNOrg     string            `json:"asn_org,omitempty"`     // source AS organisation
	Replay     bool              `json:"replay,omitempty"`      // true when replayed from history
	ClientData string            `json:"client_data,omitempty"` // hex of the first bytes sent by the client (capped)
	Detail     string            `json:"detail,omitempty"`      // one-line human summary (request line, credentials…)
	Tags       []string          `json:"tags,omitempty"`        // classifier labels, e.g. "log4shell", "scanner:zgrab"
	Meta       map[string]string `json:"meta,omitempty"`        // structured extras: ja3, ja4, sni, user, ssh_client…
}

// JoinTags serialises tags for storage.
func JoinTags(tags []string) string { return strings.Join(tags, ",") }

// SplitTags is the inverse of JoinTags.
func SplitTags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
