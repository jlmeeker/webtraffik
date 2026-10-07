package geo

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/sams96/rgeo"
	"github.com/twpayne/go-geom"
)

// GeoLocator wraps the MaxMind GeoLite2 City database with a local reverse
// geocoder fallback for IPs that only resolve to country level.
type GeoLocator struct {
	city atomic.Pointer[geoip2.Reader]
	asn  atomic.Pointer[geoip2.Reader] // optional
	rgeo atomic.Pointer[rgeo.Rgeo]     // nil until background init completes
}

// Location holds the result of an IP lookup.
type Location struct {
	Lat            float64
	Lon            float64
	City           string
	CountryCode    string
	AccuracyRadius uint16 // km; MaxMind accuracy radius (large = country-level, small = city-level)
	ASN            uint32 // autonomous system number, 0 if unknown
	ASNOrg         string // autonomous system organisation
}

// NewGeoLocator opens the GeoLite2 City .mmdb database. If enableRgeo is true,
// the embedded reverse geocoder is initialised in the background to provide city
// name fallback for IPs where MaxMind has coordinates but no city. Lookups that
// arrive before it is ready simply skip the fallback — no blocking, no data loss.
func NewGeoLocator(path string, enableRgeo bool) (*GeoLocator, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}

	g := &GeoLocator{}
	g.city.Store(db)

	if enableRgeo {
		go func() {
			rg, err := rgeo.New(rgeo.Cities10, rgeo.Provinces10)
			if err != nil {
				slog.Warn("rgeo init failed (city fallback disabled)", "err", err)
				return
			}
			rg.Build() // pre-build S2 index so first lookup is fast
			g.rgeo.Store(rg)
			slog.Info("rgeo ready — city fallback active")
		}()
	} else {
		slog.Info("rgeo disabled — city fallback inactive")
	}

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

	db := g.city.Load()
	if db == nil {
		return nil, fmt.Errorf("geo database not loaded")
	}
	record, err := db.City(ip)
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

	loc := &Location{
		Lat:            lat,
		Lon:            lon,
		City:           city,
		CountryCode:    record.Country.IsoCode,
		AccuracyRadius: record.Location.AccuracyRadius,
	}
	if adb := g.asn.Load(); adb != nil {
		if rec, err := adb.ASN(ip); err == nil {
			loc.ASN = uint32(rec.AutonomousSystemNumber)
			loc.ASNOrg = rec.AutonomousSystemOrganization
		}
	}
	return loc, nil
}

// swap installs a new reader and closes the previous one after a grace period
// so in-flight lookups finish safely.
func swap(slot *atomic.Pointer[geoip2.Reader], next *geoip2.Reader) {
	if old := slot.Swap(next); old != nil {
		time.AfterFunc(time.Minute, func() { old.Close() })
	}
}

// ReloadCity reopens the City database from path (after a refresh).
func (g *GeoLocator) ReloadCity(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	swap(&g.city, r)
	return nil
}

// LoadASN opens (or reopens) the optional ASN database.
func (g *GeoLocator) LoadASN(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	swap(&g.asn, r)
	return nil
}

// Close releases the database file handle.
func (g *GeoLocator) Close() {
	// Lookups racing with shutdown (dashboard handlers still running) must not
	// touch an unmapped file: detach first (they then get an error) and unmap
	// after a grace period.
	swap(&g.city, nil)
	swap(&g.asn, nil)
}
