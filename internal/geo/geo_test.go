package geo

import (
	"path/filepath"
	"testing"

	"webtraffik/internal/testutil"
)

func TestLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), CityFilename)
	testutil.WriteCityDB(t, path)
	g, err := NewGeoLocator(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	loc, err := g.Lookup("203.0.113.7")
	if err != nil || loc.City != "Berlin" || loc.CountryCode != "DE" || loc.AccuracyRadius != 10 {
		t.Errorf("Lookup = %+v, %v", loc, err)
	}
	loc, err = g.Lookup("2001:db8::1")
	if err != nil || loc.CountryCode != "AU" {
		t.Errorf("IPv6 lookup = %+v, %v", loc, err)
	}
	if _, err := g.Lookup("not-an-ip"); err == nil {
		t.Error("invalid IP should error")
	}
	// Hot reload swaps the reader without breaking lookups.
	if err := g.ReloadCity(path); err != nil {
		t.Fatal(err)
	}
	if loc, _ := g.Lookup("198.51.100.1"); loc == nil || loc.City != "Tokyo" {
		t.Errorf("lookup after reload = %+v", loc)
	}
}
