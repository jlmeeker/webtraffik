package db

import (
	"time"

	"webtraffik/internal/intel"
)

func intelInfo(ip string) intel.Info {
	return intel.Info{IP: ip, RDNS: "x.shodan.io", Scanner: "Shodan", AbuseScore: 7, Updated: time.Now()}
}
