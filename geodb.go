package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// Public mirror of GeoLite2-City.mmdb updated weekly — no license key required.
	// Source: https://github.com/P3TERX/GeoLite.mmdb
	geoliteURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	dbFilename = "GeoLite2-City.mmdb"
)

// ensureGeoDB returns the path to the GeoLite2 City database,
// downloading it if it doesn't already exist.
func ensureGeoDB() (string, error) {
	// Check current directory first, then the user's config dir
	localPath := dbFilename
	if _, err := os.Stat(localPath); err == nil {
		log.Printf("Using existing GeoLite2 database: %s", localPath)
		return localPath, nil
	}

	// Also check next to the executable
	execDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err == nil {
		execPath := filepath.Join(execDir, dbFilename)
		if _, err2 := os.Stat(execPath); err2 == nil {
			log.Printf("Using existing GeoLite2 database: %s", execPath)
			return execPath, nil
		}
	}

	log.Printf("GeoLite2 database not found — downloading from GitHub mirror...")
	destPath := localPath
	if err := downloadFile(destPath, geoliteURL); err != nil {
		return "", fmt.Errorf("download GeoLite2 DB: %w", err)
	}
	log.Printf("GeoLite2 database downloaded to: %s", destPath)
	return destPath, nil
}

// downloadFile downloads url to dest with a progress log.
func downloadFile(dest, url string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	log.Printf("Downloaded %.1f MB", float64(written)/1024/1024)
	return nil
}
