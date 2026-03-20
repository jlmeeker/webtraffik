package main

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoLocator wraps the MaxMind GeoLite2 City database
type GeoLocator struct {
	db *geoip2.Reader
}

// Location holds the result of an IP lookup
type Location struct {
	Lat         float64
	Lon         float64
	City        string
	CountryCode string
}

// NewGeoLocator opens the GeoLite2 City .mmdb database
func NewGeoLocator(path string) (*GeoLocator, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}
	return &GeoLocator{db: db}, nil
}

// Lookup geolocates an IP address string
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

	return &Location{
		Lat:         record.Location.Latitude,
		Lon:         record.Location.Longitude,
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
