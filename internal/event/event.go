package event

// ConnectionEvent is sent to the browser over WebSocket and persisted to SQLite.
type ConnectionEvent struct {
	Time       string  `json:"time"`
	SrcIP      string  `json:"src_ip"`
	DstIP      string  `json:"dst_ip"`
	DstPort    string  `json:"dst_port"`
	Protocol   string  `json:"protocol"` // "tcp" or "udp"
	SrcLat     float64 `json:"src_lat"`
	SrcLon     float64 `json:"src_lon"`
	DstLat     float64 `json:"dst_lat"`
	DstLon     float64 `json:"dst_lon"`
	SrcCity    string  `json:"src_city"`
	DstCity    string  `json:"dst_city"`
	SrcCC      string  `json:"src_cc"`
	DstCC      string  `json:"dst_cc"`
	Replay     bool    `json:"replay,omitempty"`      // true when replayed from history
	ClientData string  `json:"client_data,omitempty"` // hex-encoded first bytes from client (ephemeral, not persisted)
}
