package geo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchRejectsBadDownloads(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.mmdb")

	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>rate limited</html>"))
	}))
	defer small.Close()
	if _, err := fetch(context.Background(), Source{Path: dest, URL: small.URL}, false); err == nil || !strings.Contains(err.Error(), "too small") {
		t.Errorf("small download: err = %v", err)
	}

	notMMDB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", minDBSize+1)))
	}))
	defer notMMDB.Close()
	if _, err := fetch(context.Background(), Source{Path: dest, URL: notMMDB.URL}, false); err == nil || !strings.Contains(err.Error(), "not a valid database") {
		t.Errorf("garbage download: err = %v", err)
	}

	if _, err := fetch(context.Background(), Source{Path: dest, URL: notMMDB.URL, SHA256: "00"}, false); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("sha mismatch: err = %v", err)
	}

	if _, err := os.Stat(dest); err == nil {
		t.Error("a rejected download must not create the destination file")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

func TestFetchNotModified(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.mmdb")
	os.WriteFile(dest+".meta", []byte(`{"etag":"abc"}`), 0o644)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "abc" {
			t.Errorf("conditional header missing")
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	updated, err := fetch(context.Background(), Source{Path: dest, URL: srv.URL}, true)
	if err != nil || updated {
		t.Errorf("updated=%v err=%v, want false,nil", updated, err)
	}
}
