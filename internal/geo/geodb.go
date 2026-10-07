package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Default public mirror of the GeoLite2 databases (updated regularly, no
// licence key required). Override with the geo-city-url / geo-asn-url settings.
const (
	DefaultCityURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	DefaultASNURL  = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"
	CityFilename   = "GeoLite2-City.mmdb"
	ASNFilename    = "GeoLite2-ASN.mmdb"

	// minDBSize rejects truncated or error-page downloads.
	minDBSize = 1 << 20
)

// Source describes one downloadable database.
type Source struct {
	Path   string // local file path
	URL    string // download URL ("" disables downloading)
	SHA256 string // optional expected hex digest of the file
}

type validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// Ensure returns src.Path, downloading the database first when it is missing.
func Ensure(src Source) (string, error) {
	if _, err := os.Stat(src.Path); err == nil {
		slog.Info("geo: using existing database", "path", src.Path)
		return src.Path, nil
	}
	if src.URL == "" {
		return "", fmt.Errorf("geo: %s not found and no download URL configured", src.Path)
	}
	slog.Info("geo: database not found, downloading", "path", src.Path, "url", src.URL)
	if _, err := fetch(context.Background(), src, false); err != nil {
		return "", fmt.Errorf("geo: download %s: %w", src.Path, err)
	}
	return src.Path, nil
}

// fetch downloads src to a temp file, validates it as a MaxMind database (and
// against src.SHA256 when set), then atomically replaces src.Path. When force is
// false and validators from a previous download exist, a conditional request is
// made and (false, nil) is returned if the file is unchanged.
func fetch(ctx context.Context, src Source, conditional bool) (updated bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return false, err
	}
	metaPath := src.Path + ".meta"
	var prev validators
	if conditional {
		if b, err := os.ReadFile(metaPath); err == nil {
			_ = json.Unmarshal(b, &prev)
		}
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(src.Path), filepath.Base(src.Path)+".tmp-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if n < minDBSize {
		return false, fmt.Errorf("download too small (%d bytes)", n)
	}
	if want := strings.ToLower(strings.TrimSpace(src.SHA256)); want != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return false, fmt.Errorf("sha256 mismatch: got %s, want %s", got, want)
		}
	}
	if err := verifyMMDB(tmpName); err != nil {
		return false, fmt.Errorf("downloaded file is not a valid database: %w", err)
	}
	if err := os.Rename(tmpName, src.Path); err != nil {
		return false, err
	}
	v := validators{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	if b, err := json.Marshal(v); err == nil {
		_ = os.WriteFile(metaPath, b, 0o644)
	}
	slog.Info("geo: database updated", "path", src.Path, "mb", fmt.Sprintf("%.1f", float64(n)/1024/1024))
	return true, nil
}

func verifyMMDB(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()
	return r.Verify()
}

// RefreshLoop periodically re-downloads src (conditionally) and calls onUpdate
// with the path after each successful replacement, until ctx is cancelled.
func RefreshLoop(ctx context.Context, src Source, every time.Duration, onUpdate func()) {
	if every <= 0 || src.URL == "" {
		return
	}
	if src.SHA256 != "" {
		// A pinned digest only matches one specific file; refreshing would
		// fail the check as soon as upstream publishes a newer database.
		slog.Info("geo: refresh disabled because a SHA-256 pin is set", "path", src.Path)
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			updated, err := fetch(ctx, src, true)
			switch {
			case err != nil && !errors.Is(err, context.Canceled):
				slog.Warn("geo: refresh failed", "path", src.Path, "err", err)
			case updated:
				onUpdate()
			}
		}
	}
}
