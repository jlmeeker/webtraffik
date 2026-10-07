package services

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// bannerHandler sends a canned banner, reads a little client data, and closes.
func bannerHandler(banner func() []byte) ConnHandler {
	return func(ctx context.Context, c net.Conn, srcIP string) Result {
		if b := banner(); len(b) > 0 {
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			c.Write(b)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		return Result{Data: buf[:n], Tags: Classify(string(buf[:n]), "")}
	}
}

// customHandlers returns the interactive emulators keyed by port. Every port in
// customTCPPorts must have an entry.
func (e *Env) customHandlers() (map[int]ConnHandler, error) {
	ssh, err := e.sshHandler()
	if err != nil {
		return nil, err
	}
	return map[int]ConnHandler{
		21:    ftpHandler,
		22:    ssh,
		23:    telnetHandler,
		25:    smtpHandler,
		110:   pop3Handler,
		1883:  mqttHandler,
		3306:  mysqlHandler,
		3389:  rdpHandler,
		5060:  sipTCPHandler,
		5432:  postgresHandler,
		5900:  vncHandler,
		6379:  redisHandler,
		9735:  lightningHandler,
		25565: minecraftHandler,
	}, nil
}

func minecraftHandler(_ context.Context, c net.Conn, _ string) Result {
	return Result{Data: handleMinecraftConn(c)}
}

func lightningHandler(_ context.Context, c net.Conn, _ string) Result {
	return Result{Data: handleLightningConn(c)}
}

func vncHandler(_ context.Context, c net.Conn, srcIP string) Result {
	// A repeat visitor within the window is tarpitted; give it more time.
	repeat := vncIsRepeat(srcIP)
	if repeat {
		c.SetDeadline(time.Now().Add(vncTarpitMax + 10*time.Second))
	}
	return Result{Data: handleVNCConn(c, repeat)}
}

// Run starts a listener for every registered port except those in disabled and
// blocks until ctx is cancelled and all listeners have stopped.
func (e *Env) Run(ctx context.Context, disabled map[int]bool) error {
	custom, err := e.customHandlers()
	if err != nil {
		return err
	}
	banners := map[int]func() []byte{}
	for _, s := range tcpServices {
		banners[s.Port] = s.Banner
	}

	var wg sync.WaitGroup
	start := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	start(func() { pruneVNCSeen(ctx) })

	for _, sp := range All() {
		if disabled[sp.Port] {
			slog.Info("port disabled", "port", sp.Port, "proto", sp.Proto)
			continue
		}
		switch sp.Kind {
		case KindHTTP:
			start(func() { e.ServeHTTP(ctx, sp.Port, false) })
		case KindHTTPS:
			start(func() { e.ServeHTTP(ctx, sp.Port, true) })
		case KindCustom:
			start(func() { e.ServeTCP(ctx, sp.Port, sp.Name, custom[sp.Port]) })
		case KindBanner:
			start(func() { e.ServeTCP(ctx, sp.Port, sp.Name, bannerHandler(banners[sp.Port])) })
		case KindUDP:
			start(func() { e.ServeUDP(ctx, sp.Port) })
		}
	}
	wg.Wait()
	return nil
}
