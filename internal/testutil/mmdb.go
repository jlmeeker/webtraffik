// Package testutil holds helpers shared by tests. It must only be imported
// from _test.go files so test-only dependencies stay out of the binary.
package testutil

import (
	"net"
	"os"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// City is a fake GeoIP record.
type City struct {
	CIDR     string
	Name, CC string
	Lat, Lon float64
	Accuracy uint16
}

// DefaultCities are used when WriteCityDB is called with none.
var DefaultCities = []City{
	{"203.0.113.0/24", "Berlin", "DE", 52.52, 13.405, 10},
	{"198.51.100.0/24", "Tokyo", "JP", 35.68, 139.69, 5},
	{"192.0.2.0/24", "", "US", 37.75, -97.82, 1000}, // country-level centroid
	{"2001:db8::/32", "Sydney", "AU", -33.87, 151.21, 20},
}

// WriteCityDB writes a minimal GeoLite2-City-compatible database to path.
func WriteCityDB(t testing.TB, path string, cities ...City) {
	t.Helper()
	if len(cities) == 0 {
		cities = DefaultCities
	}
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cities {
		_, n, err := net.ParseCIDR(c.CIDR)
		if err != nil {
			t.Fatal(err)
		}
		rec := mmdbtype.Map{
			"country":  mmdbtype.Map{"iso_code": mmdbtype.String(c.CC)},
			"location": mmdbtype.Map{"latitude": mmdbtype.Float64(c.Lat), "longitude": mmdbtype.Float64(c.Lon), "accuracy_radius": mmdbtype.Uint16(c.Accuracy)},
		}
		if c.Name != "" {
			rec["city"] = mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(c.Name)}}
		}
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}
