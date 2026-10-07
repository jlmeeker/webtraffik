package services

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxHTTPBody  = 4096
	nginxVersion = "nginx/1.24.0"
	nginxWelcome = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"
	nginx404Fmt  = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>%s</center>\r\n</body>\r\n</html>\r\n"
)

// connState tracks whether a connection ever produced a request, so connect-only
// probes (very common internet scans) are still recorded.
type connState struct {
	served atomic.Bool
	fp     *tlsFingerprint
}

type stateKey struct{}

// ServeHTTP runs the HTTP (or, with useTLS, HTTPS) honeypot on port until ctx
// is cancelled. It answers like a stock nginx and records the full request.
func (e *Env) ServeHTTP(ctx context.Context, port int, useTLS bool) {
	ln, err := listenTCP(ctx, port)
	if err != nil {
		slog.Error("http listener failed", "port", port, "err", err)
		return
	}
	e.serveHTTP(ctx, ln, strconv.Itoa(port), useTLS)
}

// serveHTTP serves the honeypot on an existing listener.
func (e *Env) serveHTTP(ctx context.Context, ln net.Listener, portStr string, useTLS bool) {
	var l net.Listener = &guardListener{Listener: ln, env: e, port: portStr}
	proto := "http"
	if useTLS {
		tl, err := e.newTLSListener(l, portStr)
		if err != nil {
			slog.Error("tls setup failed", "port", portStr, "err", err)
			return
		}
		l = tl
		proto = "https"
	}
	slog.Info(proto+" listener", "port", portStr)

	var states sync.Map // net.Conn -> *connState
	srv := &http.Server{
		Handler:           e.httpHandler(portStr),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			st := &connState{}
			if fc, ok := c.(*fpConn); ok {
				st.fp = fc.fp
			}
			states.Store(c, st)
			return context.WithValue(ctx, stateKey{}, st)
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			if s != http.StateClosed && s != http.StateHijacked {
				return
			}
			v, ok := states.LoadAndDelete(c)
			if !ok {
				return
			}
			st := v.(*connState)
			if st.served.Load() {
				return
			}
			// Connected (and possibly handshook) but never sent a valid request.
			cp := Capture{SrcIP: extractConnIP(c.RemoteAddr()), DstPort: portStr, Protocol: "tcp",
				Detail: "connection without HTTP request", Tags: []string{"connect-only"}}
			if st.fp != nil {
				cp.Meta = st.fp.meta()
				cp.Detail = "TLS handshake without HTTP request"
			}
			e.Capture(cp)
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		slog.Error(proto+" server stopped", "port", portStr, "err", err)
	}
}

func (e *Env) httpHandler(portStr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srcIP := extractConnIP(&addrString{r.RemoteAddr})
		var fp *tlsFingerprint
		if st, ok := r.Context().Value(stateKey{}).(*connState); ok {
			st.served.Store(true)
			fp = st.fp
		}

		body, _ := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody))
		raw := rawRequest(r, body)

		w.Header().Set("Server", nginxVersion)
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Type", "text/html")
		switch {
		case (r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/index.nginx-debian.html") &&
			(r.Method == http.MethodGet || r.Method == http.MethodHead):
			w.Header().Set("Content-Length", strconv.Itoa(len(nginxWelcome)))
			w.Header().Set("Last-Modified", "Tue, 12 Mar 2024 09:41:07 GMT")
			w.Header().Set("ETag", `"65f01403-267"`)
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				io.WriteString(w, nginxWelcome)
			}
		default:
			page := fmt.Sprintf(nginx404Fmt, nginxVersion)
			w.Header().Set("Content-Length", strconv.Itoa(len(page)))
			w.WriteHeader(http.StatusNotFound)
			if r.Method != http.MethodHead {
				io.WriteString(w, page)
			}
		}

		ua := r.UserAgent()
		detail := r.Method + " " + truncate(r.URL.RequestURI(), 200)
		if ua != "" {
			detail += "  UA=" + truncate(ua, 120)
		}
		c := Capture{
			SrcIP: srcIP, DstPort: portStr, Protocol: "tcp",
			Data:   raw,
			Detail: detail,
			Tags:   Classify(string(raw), ua),
			Meta:   map[string]string{"method": r.Method, "path": truncate(r.URL.Path, 200), "host": truncate(r.Host, 100)},
		}
		if ua != "" {
			c.Meta["user_agent"] = truncate(ua, 200)
		}
		if fp != nil {
			for k, v := range fp.meta() {
				c.Meta[k] = v
			}
		}
		e.Capture(c)
	})
}

// rawRequest reconstructs the request as text for storage and signature matching.
func rawRequest(r *http.Request, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\nHost: %s\r\n", r.Method, r.RequestURI, r.Proto, r.Host)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return clip([]byte(b.String()), maxClientData)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// addrString adapts a "host:port" string to net.Addr for extractConnIP.
type addrString struct{ s string }

func (a *addrString) Network() string { return "tcp" }
func (a *addrString) String() string  { return a.s }
