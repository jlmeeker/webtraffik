package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Info is what we know about a remote address beyond geolocation.
type Info struct {
	IP         string    `json:"ip"`
	RDNS       string    `json:"rdns,omitempty"`
	Scanner    string    `json:"scanner,omitempty"`
	GreyNoise  string    `json:"greynoise,omitempty"`   // classification: benign | malicious | unknown
	AbuseScore int       `json:"abuse_score,omitempty"` // AbuseIPDB confidence 0-100 (0 = unknown/none)
	Updated    time.Time `json:"updated"`
}

// Store persists Info across restarts so paid/rate-limited APIs are not re-hit.
type Store interface {
	GetIntel(ip string) (Info, bool)
	PutIntel(Info)
}

// Config enables the optional lookups. Reverse DNS needs no key; GreyNoise's
// community API and AbuseIPDB are used only when a key is configured.
type Config struct {
	RDNS         bool
	GreyNoiseKey string
	AbuseKey     string
	Store        Store
}

const (
	cacheTTL    = 24 * time.Hour
	storeTTL    = 7 * 24 * time.Hour
	maxCache    = 20000
	queueSize   = 512
	apiInterval = 2 * time.Second
)

// Resolver enriches source addresses in the background. Lookup never blocks:
// a miss queues the address and later events see the result.
type Resolver struct {
	cfg    Config
	mu     sync.Mutex
	cache  map[string]Info
	queued map[string]bool
	work   chan string
	client *http.Client
	lookup lookupFuncs
	done   chan struct{}
	wg     sync.WaitGroup
	// API endpoints (overridable in tests).
	greyNoiseURL string
	abuseURL     string
}

type lookupFuncs struct {
	addr func(ctx context.Context, ip string) ([]string, error)
	host func(ctx context.Context, name string) ([]string, error)
}

// NewResolver starts the background worker. It is a no-op shell when no
// enrichment is enabled (Lookup still applies the free ASN-org match).
func NewResolver(cfg Config) *Resolver {
	r := &Resolver{
		cfg: cfg, cache: map[string]Info{}, queued: map[string]bool{},
		work: make(chan string, queueSize), done: make(chan struct{}),
		client:       &http.Client{Timeout: 8 * time.Second},
		lookup:       lookupFuncs{addr: net.DefaultResolver.LookupAddr, host: net.DefaultResolver.LookupHost},
		greyNoiseURL: "https://api.greynoise.io/v3/community/",
		abuseURL:     "https://api.abuseipdb.com/api/v2/check",
	}
	if r.enabled() {
		r.wg.Add(1)
		go r.loop()
	}
	return r
}

func (r *Resolver) enabled() bool {
	return r.cfg.RDNS || r.cfg.GreyNoiseKey != "" || r.cfg.AbuseKey != ""
}

// Close stops the worker.
func (r *Resolver) Close() {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	r.wg.Wait()
}

// Lookup returns cached intelligence for ip. On a miss it queues a background
// lookup and returns ok=false. It never blocks and is safe on the capture path.
func (r *Resolver) Lookup(ip string) (Info, bool) {
	if !r.enabled() {
		return Info{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if in, ok := r.cache[ip]; ok && time.Since(in.Updated) < cacheTTL {
		return in, true
	}
	if !r.queued[ip] && publicIP(ip) {
		select {
		case r.work <- ip:
			r.queued[ip] = true
		default: // queue full: skip, a later event retries
		}
	}
	return Info{}, false
}

// Get returns whatever is known about ip without queueing (API use).
func (r *Resolver) Get(ip string) (Info, bool) {
	r.mu.Lock()
	in, ok := r.cache[ip]
	r.mu.Unlock()
	if ok {
		return in, true
	}
	if r.cfg.Store != nil {
		return r.cfg.Store.GetIntel(ip)
	}
	return Info{}, false
}

func (r *Resolver) loop() {
	defer r.wg.Done()
	var lastAPI time.Time
	for {
		select {
		case <-r.done:
			return
		case ip := <-r.work:
			in := r.resolve(ip, &lastAPI)
			r.mu.Lock()
			if len(r.cache) >= maxCache {
				r.cache = map[string]Info{} // crude bound; entries are cheap to rebuild
			}
			r.cache[ip] = in
			delete(r.queued, ip)
			r.mu.Unlock()
		}
	}
}

func (r *Resolver) resolve(ip string, lastAPI *time.Time) Info {
	if r.cfg.Store != nil {
		if in, ok := r.cfg.Store.GetIntel(ip); ok && time.Since(in.Updated) < storeTTL {
			return in
		}
	}
	in := Info{IP: ip, Updated: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if r.cfg.RDNS {
		in.RDNS, in.Scanner = r.reverse(ctx, ip)
	}
	pace := func() bool {
		if d := apiInterval - time.Since(*lastAPI); d > 0 {
			select {
			case <-time.After(d):
			case <-r.done:
				return false
			}
		}
		*lastAPI = time.Now()
		return true
	}
	if r.cfg.GreyNoiseKey != "" && pace() {
		class, name := r.greyNoise(ctx, ip)
		in.GreyNoise = class
		if class == "benign" && in.Scanner == "" && name != "" {
			in.Scanner = name
		}
	}
	if r.cfg.AbuseKey != "" && pace() {
		in.AbuseScore = r.abuse(ctx, ip)
	}
	if r.cfg.Store != nil {
		r.cfg.Store.PutIntel(in)
	}
	return in
}

// reverse resolves the PTR name and forward-confirms it, so a spoofed PTR
// cannot claim to be a known scanner.
func (r *Resolver) reverse(ctx context.Context, ip string) (name, scanner string) {
	names, err := r.lookup.addr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "", ""
	}
	name = strings.TrimSuffix(names[0], ".")
	if len(name) > 255 {
		name = name[:255]
	}
	s := MatchRDNS(name)
	if s == "" {
		return name, ""
	}
	addrs, err := r.lookup.host(ctx, name)
	if err != nil {
		return name, ""
	}
	want, _ := netip.ParseAddr(ip)
	for _, a := range addrs {
		if got, err := netip.ParseAddr(a); err == nil && got.Unmap() == want.Unmap() {
			return name, s
		}
	}
	return name, ""
}

func (r *Resolver) getJSON(ctx context.Context, u string, hdr map[string]string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.Unmarshal(body, v)
}

func (r *Resolver) greyNoise(ctx context.Context, ip string) (class, name string) {
	var out struct {
		Classification string `json:"classification"`
		Name           string `json:"name"`
	}
	code, err := r.getJSON(ctx, r.greyNoiseURL+url.PathEscape(ip), map[string]string{"key": r.cfg.GreyNoiseKey, "Accept": "application/json"}, &out)
	if err != nil {
		slog.Debug("intel: greynoise", "ip", ip, "err", err)
		return "", ""
	}
	if code != http.StatusOK {
		return "", ""
	}
	if n := out.Name; n != "" && n != "unknown" {
		name = n
	}
	return out.Classification, name
}

func (r *Resolver) abuse(ctx context.Context, ip string) int {
	var out struct {
		Data struct {
			Score int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	u := fmt.Sprintf("%s?ipAddress=%s&maxAgeInDays=90", r.abuseURL, url.QueryEscape(ip))
	code, err := r.getJSON(ctx, u, map[string]string{"Key": r.cfg.AbuseKey, "Accept": "application/json"}, &out)
	if err != nil || code != http.StatusOK {
		return 0
	}
	return out.Data.Score
}

func publicIP(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && !a.IsUnspecified()
}
