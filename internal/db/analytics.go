package db

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"webtraffik/internal/event"
	"webtraffik/internal/intel"
)

// TopItem is one row of a top-N ranking with its trend against the previous
// period of equal length.
type TopItem struct {
	Key      string   `json:"key"`
	Count    int      `json:"count"`
	IPs      int      `json:"ips"`
	Prev     int      `json:"prev"`
	DeltaPct *float64 `json:"delta_pct,omitempty"` // nil when Prev == 0 ("new")
}

// TopResult is the /api/top response.
type TopResult struct {
	By    string    `json:"by"`
	Hours int       `json:"hours"`
	Items []TopItem `json:"items"`
}

// topExprs maps a ranking dimension to the SQL expression producing its key
// (NULL or ” rows are skipped).
var topExprs = map[string]string{
	"credentials": `json_extract(` + metaJSON + `,'$.user') || ':' || json_extract(` + metaJSON + `,'$.secret')`,
	"usernames":   `json_extract(` + metaJSON + `,'$.user')`,
	"passwords":   `json_extract(` + metaJSON + `,'$.secret')`,
	"useragents":  `json_extract(` + metaJSON + `,'$.user_agent')`,
	"paths":       `json_extract(` + metaJSON + `,'$.path')`,
	"ja4":         `json_extract(` + metaJSON + `,'$.ja4')`,
	"asns":        `CASE WHEN asn > 0 THEN 'AS' || asn || ' ' || asn_org END`,
	"ports":       `CAST(dst_port AS TEXT)`,
	"countries":   `NULLIF(src_cc,'')`,
	"scanners":    `NULLIF(scanner,'')`,
}

// TopDimensions lists the valid "by" values.
func TopDimensions() []string {
	d := []string{"tags"}
	for k := range topExprs {
		d = append(d, k)
	}
	sort.Strings(d)
	return d
}

// maxTopHours bounds the window (two windows are scanned).
const maxTopHours = 24 * 30

// TopN ranks one dimension over the last `hours` and compares it to the
// preceding period.
func (e *EventDB) TopN(by string, hours, limit int, now time.Time) (TopResult, error) {
	if hours <= 0 {
		hours = 24
	}
	hours = min(hours, maxTopHours)
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	cur := now.Add(-time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339)
	prev := now.Add(-2 * time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339)
	res := TopResult{By: by, Hours: hours, Items: []TopItem{}}

	if by == "tags" {
		items, err := e.topTags(cur, prev, limit)
		res.Items = items
		return res, err
	}
	expr, ok := topExprs[by]
	if !ok {
		return res, fmt.Errorf("unknown dimension %q", by)
	}
	rows, err := e.db.Query(`
		SELECT k, SUM(time >= ?1), COUNT(DISTINCT CASE WHEN time >= ?1 THEN src_ip END), SUM(time < ?1)
		FROM (SELECT `+expr+` AS k, time, src_ip FROM events WHERE time >= ?2)
		WHERE k IS NOT NULL AND k != '' AND k != ':'
		GROUP BY k HAVING SUM(time >= ?1) > 0
		ORDER BY 2 DESC, k LIMIT ?3`, cur, prev, limit)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Key, &it.Count, &it.IPs, &it.Prev); err != nil {
			return res, err
		}
		it.setDelta()
		res.Items = append(res.Items, it)
	}
	return res, rows.Err()
}

func (t *TopItem) setDelta() {
	if t.Prev > 0 {
		d := float64(t.Count-t.Prev) / float64(t.Prev) * 100
		t.DeltaPct = &d
	}
}

func (e *EventDB) topTags(cur, prev string, limit int) ([]TopItem, error) {
	rows, err := e.db.Query(`SELECT tags, src_ip, time >= ? FROM events WHERE tags != '' AND time >= ?`, cur, prev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		it  TopItem
		ips map[string]bool
	}
	m := map[string]*acc{}
	for rows.Next() {
		var tags, ip string
		var isCur bool
		if err := rows.Scan(&tags, &ip, &isCur); err != nil {
			return nil, err
		}
		for _, t := range event.SplitTags(tags) {
			a := m[t]
			if a == nil {
				a = &acc{it: TopItem{Key: t}, ips: map[string]bool{}}
				m[t] = a
			}
			if isCur {
				a.it.Count++
				a.ips[ip] = true
			} else {
				a.it.Prev++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TopItem, 0, len(m))
	for _, a := range m {
		if a.it.Count == 0 {
			continue
		}
		a.it.IPs = len(a.ips)
		a.it.setDelta()
		out = append(out, a.it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// maxCampaignRows bounds the rows scanned for clustering.
const maxCampaignRows = 200000

// Campaigns clusters recent fingerprinted events (see intel.Cluster).
func (e *EventDB) Campaigns(hours, limit int, now time.Time) ([]intel.Campaign, error) {
	if hours <= 0 {
		hours = 72
	}
	hours = min(hours, maxTopHours)
	since := now.Add(-time.Duration(hours) * time.Hour).UTC().Format(time.RFC3339)
	rows, err := e.db.Query(`SELECT src_ip, fp, dst_port, src_cc, tags, time FROM events
		WHERE fp != '' AND time >= ? ORDER BY id DESC LIMIT ?`, since, maxCampaignRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var data []intel.FPRow
	for rows.Next() {
		var ip, fp, cc, tags, ts string
		var port int
		if err := rows.Scan(&ip, &fp, &port, &cc, &tags, &ts); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, ts)
		data = append(data, intel.FPRow{IP: ip, FP: strings.Split(fp, ","), Port: port, CC: cc, Tags: event.SplitTags(tags), Time: t})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return intel.Cluster(data, 2, limit), nil
}

// GetIntel implements intel.Store.
func (e *EventDB) GetIntel(ip string) (intel.Info, bool) {
	var in intel.Info
	var upd string
	err := e.db.QueryRow(`SELECT ip, rdns, scanner, greynoise, abuse_score, updated FROM ip_intel WHERE ip = ?`, ip).
		Scan(&in.IP, &in.RDNS, &in.Scanner, &in.GreyNoise, &in.AbuseScore, &upd)
	if err != nil {
		return intel.Info{}, err == nil
	}
	in.Updated, _ = time.Parse(time.RFC3339, upd)
	return in, true
}

// PutIntel implements intel.Store.
func (e *EventDB) PutIntel(in intel.Info) {
	_, _ = e.db.Exec(`INSERT OR REPLACE INTO ip_intel (ip, rdns, scanner, greynoise, abuse_score, updated) VALUES (?,?,?,?,?,?)`,
		in.IP, in.RDNS, in.Scanner, in.GreyNoise, in.AbuseScore, in.Updated.UTC().Format(time.RFC3339))
}
