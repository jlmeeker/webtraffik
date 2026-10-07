package services

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxConns bounds concurrent emulated connections across all listeners.
	DefaultMaxConns = 4096
	// connDeadline is the hard cap on one emulated session (tarpits excepted).
	connDeadline = 30 * time.Second
	// maxClientData is the most client bytes kept per capture.
	maxClientData = 4096
)

// Env carries the dependencies shared by every listener.
type Env struct {
	IsBanned IsBannedFunc
	Capture  CaptureFunc
	DataDir  string // where host keys / certificates are persisted

	sem      chan struct{}
	rejected atomic.Uint64
}

// NewEnv builds an Env limiting concurrent connections to maxConns.
func NewEnv(isBanned IsBannedFunc, capture CaptureFunc, dataDir string, maxConns int) *Env {
	if maxConns <= 0 {
		maxConns = DefaultMaxConns
	}
	return &Env{IsBanned: isBanned, Capture: capture, DataDir: dataDir, sem: make(chan struct{}, maxConns)}
}

// Rejected returns how many connections were refused because the concurrency
// limit was reached.
func (e *Env) Rejected() uint64 { return e.rejected.Load() }

// Active returns the number of connections currently being served.
func (e *Env) Active() int { return len(e.sem) }

// acquire reserves a connection slot without blocking.
func (e *Env) acquire() bool {
	select {
	case e.sem <- struct{}{}:
		return true
	default:
		e.rejected.Add(1)
		return false
	}
}

func (e *Env) release() { <-e.sem }

// guardListener drops banned peers and enforces the connection limit at
// accept time; accepted connections release their slot when closed.
type guardListener struct {
	net.Listener
	env  *Env
	port string
}

func (g *guardListener) Accept() (net.Conn, error) {
	for {
		c, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if g.env.IsBanned(extractConnIP(c.RemoteAddr()), g.port) {
			c.Close()
			continue
		}
		if !g.env.acquire() {
			c.Close()
			continue
		}
		return &slotConn{Conn: c, env: g.env}, nil
	}
}

type slotConn struct {
	net.Conn
	env  *Env
	once sync.Once
}

func (s *slotConn) Close() error {
	err := s.Conn.Close()
	s.once.Do(s.env.release)
	return err
}

// listenTCP binds the port and arranges for the listener to close with ctx.
func listenTCP(ctx context.Context, port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	return ln, nil
}

// ServeTCP runs an accept loop on port, passing each connection to h, until
// ctx is cancelled.
func (e *Env) ServeTCP(ctx context.Context, port int, name string, h ConnHandler) {
	ln, err := listenTCP(ctx, port)
	if err != nil {
		slog.Error("tcp listener failed", "port", port, "service", name, "err", err)
		return
	}
	slog.Info("tcp listener", "port", port, "service", name)
	e.serveTCP(ctx, ln, strconv.Itoa(port), name, h)
}

// serveTCP runs the accept loop on an existing listener.
func (e *Env) serveTCP(ctx context.Context, ln net.Listener, portStr, name string, h ConnHandler) {
	port := portStr
	g := &guardListener{Listener: ln, env: e, port: portStr}

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := g.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("tcp accept", "port", port, "err", err)
			time.Sleep(time.Second)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("handler panic", "port", port, "service", name, "panic", r)
				}
			}()
			srcIP := extractConnIP(c.RemoteAddr())
			c.SetDeadline(time.Now().Add(connDeadline))
			// On shutdown, unblock handlers stuck in reads/sleeps promptly
			// instead of waiting out the session deadline.
			stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
			defer stop()
			res := h(ctx, c, srcIP)
			e.Capture(Capture{
				SrcIP: srcIP, DstPort: portStr, Protocol: "tcp",
				Data: clip(res.Data, maxClientData), Detail: res.Detail, Tags: res.Tags, Meta: res.Meta,
			})
		}()
	}
}

// ServeUDP records every datagram received on port. No reply is sent, and bans
// are not consulted (UDP is connectionless; the source can be spoofed).
func (e *Env) ServeUDP(ctx context.Context, port int) {
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("udp listener failed", "port", port, "err", err)
		return
	}
	go func() { <-ctx.Done(); pc.Close() }()
	slog.Info("udp listener", "port", port)
	portStr := strconv.Itoa(port)

	buf := make([]byte, 2048)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("udp read", "port", port, "err", err)
			time.Sleep(time.Second)
			continue
		}
		data := make([]byte, min(n, 512))
		copy(data, buf)
		e.Capture(Capture{SrcIP: extractConnIP(src), DstPort: portStr, Protocol: "udp", Data: data})
	}
}
