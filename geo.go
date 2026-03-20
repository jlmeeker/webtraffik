package main

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/sams96/rgeo"
	"github.com/twpayne/go-geom"
)

// GeoLocator wraps the MaxMind GeoLite2 City database with a local reverse
// geocoder fallback for IPs that only resolve to country level.
type GeoLocator struct {
	db   *geoip2.Reader
	rgeo *rgeo.Rgeo
}

// Location holds the result of an IP lookup
type Location struct {
	Lat         float64
	Lon         float64
	City        string
	CountryCode string
}

// NewGeoLocator opens the GeoLite2 City .mmdb database and initialises the
// embedded reverse geocoder (Cities10 dataset, ~10 MB embedded in binary).
func NewGeoLocator(path string) (*GeoLocator, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}

	rg, err := rgeo.New(rgeo.Cities10, rgeo.Provinces10)
	if err != nil {
		// Non-fatal: fall back gracefully if rgeo fails to init
		rg = nil
	}

	return &GeoLocator{db: db, rgeo: rg}, nil
}

// Lookup geolocates an IP address string.
// If GeoLite2 has no city name but does have coordinates, it falls back to a
// local reverse geocode (rgeo) to resolve the nearest city/province.
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
	if city == "" && g.rgeo != nil && (lat != 0 || lon != 0) {
		if loc, rerr := g.rgeo.ReverseGeocode(geom.Coord{lon, lat}); rerr == nil {
			if loc.City != "" {
				city = loc.City
			} else if loc.Province != "" {
				city = loc.Province
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

// Close releases the database file handle
func (g *GeoLocator) Close() {
	if g.db != nil {
		g.db.Close()
	}
}
