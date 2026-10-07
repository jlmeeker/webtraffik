package intel

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"time"
)

// FPRow is one stored event reduced to what clustering needs.
type FPRow struct {
	IP      string
	FP      []string
	Port    int
	CC      string
	Tags    []string
	Time    time.Time
	Scanner string
}

// Campaign is a set of events linked by shared fingerprints: the same TLS
// client hash or attack payload seen from several addresses.
type Campaign struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	IPs       []string `json:"ips"`
	IPCount   int      `json:"ip_count"`
	Events    int      `json:"events"`
	Ports     []int    `json:"ports"`
	Countries []string `json:"countries"`
	Tags      []string `json:"tags"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

// maxCampaignIPs bounds the IP list returned per campaign.
const maxCampaignIPs = 50

// Cluster groups rows into campaigns with union-find over fingerprints (two
// events sharing any fingerprint are one campaign) and returns those seen from
// at least minIPs addresses, largest first.
func Cluster(rows []FPRow, minIPs, limit int) []Campaign {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if rb < ra { // deterministic root: the smallest fingerprint
			ra, rb = rb, ra
		}
		parent[rb] = ra
	}
	for _, r := range rows {
		for _, f := range r.FP {
			if _, ok := parent[f]; !ok {
				parent[f] = f
			}
			union(r.FP[0], f)
		}
	}

	type agg struct {
		ips     map[string]bool
		ports   map[int]bool
		ccs     map[string]bool
		tags    map[string]bool
		fps     map[string]int
		events  int
		first   time.Time
		last    time.Time
		scanner bool
	}
	groups := map[string]*agg{}
	for _, r := range rows {
		if len(r.FP) == 0 {
			continue
		}
		root := find(r.FP[0])
		g := groups[root]
		if g == nil {
			g = &agg{ips: map[string]bool{}, ports: map[int]bool{}, ccs: map[string]bool{}, tags: map[string]bool{}, fps: map[string]int{}}
			groups[root] = g
		}
		g.events++
		g.ips[r.IP] = true
		g.ports[r.Port] = true
		if r.CC != "" {
			g.ccs[r.CC] = true
		}
		for _, t := range r.Tags {
			g.tags[t] = true
		}
		for _, f := range r.FP {
			g.fps[f]++
		}
		if g.first.IsZero() || r.Time.Before(g.first) {
			g.first = r.Time
		}
		if r.Time.After(g.last) {
			g.last = r.Time
		}
	}

	out := make([]Campaign, 0, len(groups))
	for root, g := range groups {
		if len(g.ips) < minIPs {
			continue
		}
		sum := sha1.Sum([]byte(root))
		c := Campaign{
			ID: "c-" + hex.EncodeToString(sum[:3]), Label: topKey(g.fps),
			IPCount: len(g.ips), Events: g.events,
			Ports: sortedInts(g.ports), Countries: sortedStrs(g.ccs), Tags: sortedStrs(g.tags),
			FirstSeen: g.first.UTC().Format(time.RFC3339), LastSeen: g.last.UTC().Format(time.RFC3339),
		}
		c.IPs = sortedStrs(g.ips)
		if len(c.IPs) > maxCampaignIPs {
			c.IPs = c.IPs[:maxCampaignIPs]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPCount != out[j].IPCount {
			return out[i].IPCount > out[j].IPCount
		}
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func topKey(m map[string]int) string {
	best, n := "", -1
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func sortedStrs[M ~map[string]bool](m M) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func sortedInts(m map[int]bool) []int {
	s := make([]int, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Ints(s)
	return s
}
