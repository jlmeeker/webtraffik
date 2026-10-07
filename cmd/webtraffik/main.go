// Command webtraffik is a network traffic sensor and honeypot with a live
// world-map dashboard. See README.md for an overview.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"webtraffik/internal/app"
	"webtraffik/internal/ebpf"
	"webtraffik/internal/geo"
	"webtraffik/internal/server"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "ports":
			os.Exit(portsCommand(os.Args[2:], os.Stdout, os.Stderr))
		case "version", "-version", "--version":
			fmt.Println("webtraffik", version)
			return
		}
	}
	if err := run(os.Args[1:]); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			return nil
		}
		return err
	}
	setupLogging(cfg.LogLevel, cfg.LogFormat)
	slog.Info("webTraffik starting", "version", version)

	opts, srvCfg, err := buildOptions(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := app.New(opts)
	if err != nil {
		return err
	}
	srv := server.New(a, srvCfg)

	// SIGHUP reloads the eBPF management allow-list without a restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				slog.Info("SIGHUP: reloading mgmt allow file")
				if err := a.ReloadAllowFile(); err != nil {
					slog.Error("allow file reload failed", "err", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Serve(ctx) }()

	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(ctx) }()

	select {
	case err := <-srvErr:
		// The dashboard failing to start (port in use…) is fatal; a clean
		// shutdown returns nil here only after ctx is cancelled.
		stop()
		<-runErr
		return err
	case err := <-runErr:
		stop()
		<-srvErr
		return err
	case <-ctx.Done():
		slog.Info("shutting down…")
		done := make(chan struct{})
		go func() { <-runErr; <-srvErr; close(done) }()
		select {
		case <-done:
			slog.Info("shutdown complete")
		case <-time.After(20 * time.Second):
			slog.Warn("shutdown timed out; exiting")
		}
		return nil
	}
}

// buildOptions converts the parsed Config into app and server options.
func buildOptions(cfg Config) (app.Options, server.Config, error) {
	var zeroApp app.Options
	var zeroSrv server.Config

	mode, err := ebpf.ParseCaptureMode(cfg.CaptureMode)
	if err != nil {
		slog.Warn("invalid capture-mode, defaulting to go-only", "err", err)
		mode = ebpf.ModeGoOnly
	}
	disabled, err := parsePortSet(cfg.DisablePorts)
	if err != nil {
		return zeroApp, zeroSrv, fmt.Errorf("disable-ports: %w", err)
	}
	mgmt, err := parsePortList(cfg.MgmtPorts)
	if err != nil {
		return zeroApp, zeroSrv, fmt.Errorf("mgmt-ports: %w", err)
	}

	dataDir := cfg.DataDir
	if dataDir == "" {
		if dataDir, err = os.Getwd(); err != nil {
			dataDir = "."
		}
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return zeroApp, zeroSrv, fmt.Errorf("data-dir: %w", err)
	}

	refresh := time.Duration(0)
	if cfg.GeoRefresh != "" && cfg.GeoRefresh != "0" {
		if refresh, err = time.ParseDuration(cfg.GeoRefresh); err != nil {
			return zeroApp, zeroSrv, fmt.Errorf("geo-refresh: %w", err)
		}
	}

	pass, err := resolveDashboardPass(cfg)
	if err != nil {
		return zeroApp, zeroSrv, err
	}

	opts := app.Options{
		DataDir: dataDir, CaptureMode: mode, EBPFIface: cfg.EBPFIface,
		MgmtPorts: mgmt, MgmtAllow: cfg.MgmtAllowFile, DisabledPort: disabled,
		DisableRgeo: cfg.DisableRgeo, DisableASN: cfg.DisableASN,
		GeoCity:    geo.Source{Path: joinPath(dataDir, geo.CityFilename), URL: cfg.GeoCityURL, SHA256: cfg.GeoCitySHA256},
		GeoASN:     geo.Source{Path: joinPath(dataDir, geo.ASNFilename), URL: cfg.GeoASNURL},
		GeoRefresh: refresh,
		PublicIP:   strings.TrimSpace(cfg.PublicIP), MaxConns: cfg.MaxConns,
		RetentionDays: cfg.RetentionDays, ExportJSONL: cfg.ExportJSONL, ExportMaxMB: cfg.ExportMaxMB,
		EnrichRDNS: cfg.EnrichRDNS, GreyNoiseKey: strings.TrimSpace(cfg.GreyNoiseKey), AbuseKey: strings.TrimSpace(cfg.AbuseIPDBKey),
		Version: version,
	}
	srvCfg := server.Config{
		Listen: cfg.DashboardListen, User: cfg.DashboardUser, Pass: pass,
		AllowedOrigins: splitList(cfg.AllowedOrigins),
		Static:         staticSubFS(),
	}
	return opts, srvCfg, nil
}
