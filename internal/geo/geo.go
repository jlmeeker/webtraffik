package geo

import (
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/oschwald/geoip2-golang"
	"github.com/sams96/rgeo"
	"github.com/twpayne/go-geom"
)

// GeoLocator wraps the MaxMind GeoLite2 City database with a local reverse
// geocoder fallback for IPs that only resolve to country level.
type GeoLocator struct {
	db   *geoip2.Reader
	rgeo atomic.Pointer[rgeo.Rgeo] // nil until background init completes
}

// Location holds the result of an IP lookup.
type Location struct {
	Lat         float64
	Lon         float64
	City        string
	CountryCode string
}

// NewGeoLocator opens the GeoLite2 City .mmdb database and kicks off the
// embedded reverse geocoder init in the background. Lookups that arrive before
// it is ready simply skip the city fallback — no blocking, no data loss.
func NewGeoLocator(path string) (*GeoLocator, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}

	g := &GeoLocator{db: db}

	go func() {
		rg, err := rgeo.New(rgeo.Cities10, rgeo.Provinces10)
		if err != nil {
			log.Printf("rgeo init failed (city fallback disabled): %v", err)
			return
		}
		rg.Build() // pre-build S2 index so first lookup is fast
		g.rgeo.Store(rg)
		log.Println("rgeo ready — city fallback active")
	}()

	return g, nil
}

// Lookup geolocates an IP address string.
// If GeoLite2 has no city name but does have coordinates, it falls back to a
// local reverse geocode (rgeo) to resolve the nearest city/province.
// The fallback is silently skipped if rgeo is still initialising in the background.
func (g *GeoLocator) Lookup(ipStr string) (*Location, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	record, err := g.db.City(ip)
	if err != nil {
		return nil, fmt.Errorf("city lookup: %w", err)
	}

	city := ""
	if len(record.City.Names) > 0 {
		city = record.City.Names["en"]
	}

	lat := record.Location.Latitude
	lon := record.Location.Longitude

	// Fall back to local reverse geocode when GeoLite2 has no city but has
	// valid coordinates (non-zero lat/lon means a real position was returned).
	if city == "" && (lat != 0 || lon != 0) {
		if rg := g.rgeo.Load(); rg != nil {
			if loc, rerr := rg.ReverseGeocode(geom.Coord{lon, lat}); rerr == nil {
				if loc.City != "" {
					city = loc.City
				} else if loc.Province != "" {
					city = loc.Province
				}
			}
		}
	}

	return &Location{
		Lat:         lat,
		Lon:         lon,
		City:        city,
		CountryCode: record.Country.IsoCode,
	}, nil
}

// Close releases the database file handle.
func (g *GeoLocator) Close() {
	if g.db != nil {
		g.db.Close()
	}
}
