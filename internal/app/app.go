// Package app wires the capture pipeline together: listeners and the eBPF
// event stream feed a bounded queue, workers enrich each capture (geo, ASN)
// and fan it out to the hub, database, metrics and optional JSONL export.
package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"webtraffik/internal/db"
	"webtraffik/internal/ebpf"
	"webtraffik/internal/event"
	"webtraffik/internal/geo"
	"webtraffik/internal/hub"
	"webtraffik/internal/iputil"
	"webtraffik/internal/metrics"
	"webtraffik/internal/ratelimit"
	"webtraffik/internal/services"
)

// Options configures an App.
type Options struct {
	DataDir      string
	CaptureMode  ebpf.CaptureMode
	EBPFIface    string
	MgmtPorts    []uint16
	MgmtAllow    string
	DisabledPort map[int]bool
	DisableRgeo  bool
	DisableASN   bool

	GeoCity    geo.Source
	GeoASN     geo.Source
	GeoRefresh time.Duration

	PublicIP      string // "" = auto-discover, "none" = skip
	MaxConns      int
	RetentionDays int
	ExportJSONL   string
	ExportMaxMB   int

	Version string
}

// QueueSize is the capture queue depth between listeners and workers.
const QueueSize = 8192

// App owns the runtime components shared by the capture pipeline and the
// dashboard server.
type App struct {
	Opts    Options
	Hub     *hub.Hub
	DB      *db.EventDB
	Geo     *geo.GeoLocator
	Metrics *metrics.Cache
	Limiter *ratelimit.Limiter
	EBPF    *ebpf.Manager
	Env     *services.Env
	Self    SelfInfo

	started time.Time
	qmu     sync.RWMutex // guards closing of queue against concurrent Submit
	qclosed bool
	queue   chan queued
	dropped atomic.Uint64
	handled atomic.Uint64
	export  *exporter
}

// SelfInfo describes this host (the destination end of every arc).
type SelfInfo struct {
	IP   string  `json:"ip"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	City string  `json:"city"`
	CC   string  `json:"cc"`
}

type queued struct {
	c    services.Capture
	when time.Time
}

// New opens the database and geo data and constructs every component. No
// network listeners are started until Run.
func New(opts Options) (*App, error) {
	a := &App{Opts: opts, Hub: hub.New(), started: time.Now(), queue: make(chan queued, QueueSize)}

	var err error
	if a.DB, err = db.OpenEventDB(opts.DataDir); err != nil {
		return nil, fmt.Errorf("open event database: %w", err)
	}

	a.Limiter = ratelimit.New(services.PortServiceName, func(banType string) {
		if a.Metrics != nil {
			a.Metrics.RecordBan(banType)
		}
	})
	a.Limiter.SetDB(a.DB)

	// eBPF: on any attach failure fall back to go-only and carry on.
	a.EBPF = ebpf.New(opts.CaptureMode, opts.EBPFIface, opts.MgmtPorts, opts.MgmtAllow)
	if err := a.EBPF.Start(); err != nil {
		slog.Warn("ebpf: XDP attach failed, falling back to go-only", "err", err)
		a.EBPF = ebpf.New(ebpf.ModeGoOnly, "", nil, "")
		a.Opts.CaptureMode = ebpf.ModeGoOnly // report (and behave as) go-only from here on
	}
	a.Limiter.SetEBPFManager(a.EBPF)

	if err := a.DB.BackfillMetrics(services.PortServiceName); err != nil {
		slog.Warn("metrics backfill failed", "err", err)
	}
	a.Metrics = metrics.NewCache(a.DB, services.PortServiceName)

	if history, err := a.DB.LoadHistory(hub.HistorySize); err == nil {
		a.Hub.Seed(history)
		slog.Info("loaded history", "events", len(history))
	} else {
		slog.Warn("could not load history", "err", err)
	}

	cityPath, err := geo.Ensure(opts.GeoCity)
	if err != nil {
		a.closeEarly()
		return nil, err
	}
	if a.Geo, err = geo.NewGeoLocator(cityPath, !opts.DisableRgeo); err != nil {
		a.closeEarly()
		return nil, fmt.Errorf("open GeoLite2 City database: %w", err)
	}
	if !opts.DisableASN {
		if p, err := geo.Ensure(opts.GeoASN); err != nil {
			slog.Warn("ASN database unavailable; ASN enrichment disabled", "err", err)
		} else if err := a.Geo.LoadASN(p); err != nil {
			slog.Warn("could not open ASN database", "err", err)
		}
	}

	a.Limiter.SetGeoCC(func(ip string) string {
		if loc, err := a.Geo.Lookup(ip); err == nil {
			return loc.CountryCode
		}
		return ""
	})
	a.Limiter.LoadBans()

	a.Self = a.discoverSelf()

	if opts.ExportJSONL != "" {
		if a.export, err = newExporter(opts.ExportJSONL, opts.ExportMaxMB); err != nil {
			slog.Warn("JSONL export disabled", "err", err)
		}
	}

	a.Env = services.NewEnv(a.Limiter.IsBanned, a.Submit, opts.DataDir, opts.MaxConns)
	return a, nil
}

func (a *App) closeEarly() {
	a.EBPF.Stop()
	a.Metrics.Close()
	a.DB.Close()
}

func (a *App) discoverSelf() SelfInfo {
	var self SelfInfo
	switch a.Opts.PublicIP {
	case "none":
		self.IP = "unknown"
		return self
	case "":
		ip, err := iputil.DiscoverPublicIP()
		if err != nil {
			slog.Warn("could not discover public IP (set public-ip to override)", "err", err)
			self.IP = "unknown"
			return self
		}
		self.IP = ip
	default:
		self.IP = a.Opts.PublicIP
	}
	slog.Info("public IP", "ip", self.IP)
	if loc, err := a.Geo.Lookup(self.IP); err == nil {
		self.Lat, self.Lon, self.City, self.CC = loc.Lat, loc.Lon, loc.City, loc.CountryCode
		slog.Info("self location", "city", self.City, "cc", self.CC, "lat", self.Lat, "lon", self.Lon)
	}
	return self
}

// Submit enqueues a capture for processing. It never blocks: when the queue is
// full the capture is counted and dropped, so a flood cannot stall listeners.
func (a *App) Submit(c services.Capture) {
	a.qmu.RLock()
	defer a.qmu.RUnlock()
	if a.qclosed {
		return // shutting down: stragglers from closing connections
	}
	select {
	case a.queue <- queued{c: c, when: time.Now()}:
	default:
		a.dropped.Add(1)
	}
}

// Run starts the listeners, workers and background loops and blocks until ctx
// is cancelled, then shuts everything down in order.
func (a *App) Run(ctx context.Context) error {
	var workers sync.WaitGroup
	for i := 0; i < max(2, runtime.NumCPU()); i++ {
		workers.Add(1)
		go func() { defer workers.Done(); a.worker() }()
	}

	var bg sync.WaitGroup
	spawn := func(f func()) { bg.Add(1); go func() { defer bg.Done(); f() }() }

	if a.Opts.GeoRefresh > 0 {
		spawn(func() {
			geo.RefreshLoop(ctx, a.Opts.GeoCity, a.Opts.GeoRefresh, func() {
				if err := a.Geo.ReloadCity(a.Opts.GeoCity.Path); err != nil {
					slog.Warn("geo: reload city db", "err", err)
				}
			})
		})
		if !a.Opts.DisableASN {
			spawn(func() {
				geo.RefreshLoop(ctx, a.Opts.GeoASN, a.Opts.GeoRefresh, func() {
					if err := a.Geo.LoadASN(a.Opts.GeoASN.Path); err != nil {
						slog.Warn("geo: reload asn db", "err", err)
					}
				})
			})
		}
	}
	if a.Opts.RetentionDays > 0 {
		spawn(func() { a.retentionLoop(ctx) })
	}

	if a.Opts.CaptureMode == ebpf.ModeEBPFOnly && a.EBPF.IsActive() {
		slog.Info("ebpf-only mode: Go listeners not started (service emulation unavailable)")
		spawn(func() { a.pumpEBPF(ctx, nil) })
		<-ctx.Done()
	} else {
		if a.EBPF.IsActive() {
			listened := services.ListenedPorts(a.Opts.DisabledPort)
			spawn(func() { a.pumpEBPF(ctx, listened) })
		}
		if err := a.Env.Run(ctx, a.Opts.DisabledPort); err != nil {
			slog.Error("listeners failed", "err", err)
		}
		<-ctx.Done()
	}

	// Shutdown: listeners are already closed. Drain the queue, then release
	// resources in dependency order so nothing is lost.
	bg.Wait()
	a.EBPF.Stop() // detach XDP; closes the event channel
	a.qmu.Lock()
	a.qclosed = true
	close(a.queue)
	a.qmu.Unlock()
	workers.Wait()
	a.Metrics.Close() // final flush
	if a.export != nil {
		a.export.Close()
	}
	a.DB.Close() // drains the insert queue
	a.Geo.Close()
	return nil
}

func (a *App) worker() {
	for q := range a.queue {
		a.process(q)
	}
}

// ReloadAllowFile re-reads the eBPF management allow-list (SIGHUP).
func (a *App) ReloadAllowFile() error { return a.EBPF.ReloadAllowFile() }

const maxStoredClientData = 4096

// process turns a Capture into a ConnectionEvent and fans it out.
func (a *App) process(q queued) {
	c := q.c
	// Rate-limit and scan tracking apply to TCP only; UDP/ICMP are stateless
	// (and trivially spoofed).
	if c.Protocol == "tcp" && !a.Limiter.Record(c.SrcIP, c.DstPort) {
		return
	}

	ev := event.ConnectionEvent{
		Time:     q.when.UTC().Format(time.RFC3339),
		SrcIP:    c.SrcIP,
		DstIP:    a.Self.IP,
		DstPort:  c.DstPort,
		Protocol: c.Protocol,
		DstLat:   a.Self.Lat,
		DstLon:   a.Self.Lon,
		DstCity:  a.Self.City,
		DstCC:    a.Self.CC,
		Detail:   c.Detail,
		Tags:     c.Tags,
		Meta:     c.Meta,
	}
	if len(c.Data) > 0 {
		ev.ClientData = hex.EncodeToString(c.Data[:min(len(c.Data), maxStoredClientData)])
	}
	if loc, err := a.Geo.Lookup(c.SrcIP); err == nil {
		ev.SrcLat, ev.SrcLon = loc.Lat, loc.Lon
		ev.SrcCity, ev.SrcCC = loc.City, loc.CountryCode
		ev.ASN, ev.ASNOrg = loc.ASN, loc.ASNOrg
	} else {
		slog.Debug("geo lookup failed", "ip", c.SrcIP, "err", err)
	}

	a.Hub.Broadcast(ev)
	a.DB.Insert(ev)
	a.Metrics.Record(ev)
	if a.export != nil {
		a.export.Write(ev)
	}
	a.handled.Add(1)
	slog.Debug("connection", "src", ev.SrcIP, "port", ev.DstPort, "proto", ev.Protocol, "cc", ev.SrcCC, "detail", ev.Detail)
}

// pumpEBPF feeds XDP-observed connection attempts into the pipeline. Ports with
// a Go listener are skipped (the listener reports them with richer detail).
func (a *App) pumpEBPF(ctx context.Context, listened map[services.PortKey]bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.EBPF.EventCh:
			if !ok {
				return
			}
			if ev.Dropped || listened[services.PortKey{Proto: ev.Protocol, Port: int(ev.DstPort)}] {
				continue // dropped = banned at XDP; listened = reported by its listener
			}
			a.Submit(services.Capture{
				SrcIP:    ev.SrcIP.String(),
				DstPort:  fmt.Sprint(ev.DstPort),
				Protocol: ev.Protocol,
				Detail:   "observed by XDP (no listener)",
			})
		}
	}
}

func (a *App) retentionLoop(ctx context.Context) {
	prune := func() {
		cutoff := time.Now().AddDate(0, 0, -a.Opts.RetentionDays)
		n, err := a.DB.PruneEvents(cutoff)
		if err != nil {
			slog.Warn("retention prune failed", "err", err)
		} else if n > 0 {
			slog.Info("retention: pruned old events", "deleted", n, "older_than_days", a.Opts.RetentionDays)
		}
	}
	prune()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

// Status is a point-in-time health snapshot for /api/status.
type Status struct {
	Version     string   `json:"version"`
	UptimeSec   float64  `json:"uptime_sec"`
	CaptureMode string   `json:"capture_mode"`
	EBPFActive  bool     `json:"ebpf_active"`
	Subscribers int      `json:"ws_subscribers"`
	QueueDepth  int      `json:"queue_depth"`
	QueueCap    int      `json:"queue_capacity"`
	Handled     uint64   `json:"events_handled"`
	Dropped     uint64   `json:"events_dropped"`
	ActiveConns int      `json:"active_conns"`
	RejectConns uint64   `json:"rejected_conns"`
	Self        SelfInfo `json:"self"`
}

// Status returns the current snapshot.
func (a *App) Status() Status {
	return Status{
		Version:     a.Opts.Version,
		UptimeSec:   time.Since(a.started).Seconds(),
		CaptureMode: a.Opts.CaptureMode.String(),
		EBPFActive:  a.EBPF.IsActive(),
		Subscribers: a.Hub.Subscribers(),
		QueueDepth:  len(a.queue),
		QueueCap:    cap(a.queue),
		Handled:     a.handled.Load(),
		Dropped:     a.dropped.Load(),
		ActiveConns: a.Env.Active(),
		RejectConns: a.Env.Rejected(),
		Self:        a.Self,
	}
}
