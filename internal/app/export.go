package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"webtraffik/internal/event"
)

// exporter appends every event as one JSON object per line (JSONL) to a file,
// rotating to <path>.1 when it exceeds maxBytes. It is intended for shipping to
// a log pipeline (Filebeat, Vector, Loki…).
type exporter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	w        *bufio.Writer
	size     int64
}

func newExporter(path string, maxMB int) (*exporter, error) {
	if maxMB <= 0 {
		maxMB = 100
	}
	x := &exporter{path: path, maxBytes: int64(maxMB) << 20}
	if err := x.open(); err != nil {
		return nil, err
	}
	slog.Info("JSONL export enabled", "path", path, "rotate_mb", maxMB)
	return x, nil
}

func (x *exporter) open() error {
	f, err := os.OpenFile(x.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	x.f, x.w, x.size = f, bufio.NewWriterSize(f, 64<<10), st.Size()
	return nil
}

func (x *exporter) Write(ev event.ConnectionEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.size+int64(len(b))+1 > x.maxBytes {
		if err := x.rotate(); err != nil {
			slog.Warn("export rotate failed", "err", err)
			return
		}
	}
	n, _ := x.w.Write(b)
	x.w.WriteByte('\n')
	x.size += int64(n) + 1
	// Flush per event: capture rates are modest and a crash should not lose
	// the tail of the log.
	x.w.Flush()
}

func (x *exporter) rotate() error {
	x.w.Flush()
	x.f.Close()
	if err := os.Rename(x.path, fmt.Sprintf("%s.1", x.path)); err != nil {
		return err
	}
	return x.open()
}

func (x *exporter) Close() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.w.Flush()
	x.f.Close()
}
