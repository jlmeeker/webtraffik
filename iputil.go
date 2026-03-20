package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Public IP discovery services — tried in order until one succeeds
var ipServices = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://ifconfig.me/ip",
}

// discoverPublicIP queries external services to find our public IPv4 address
func discoverPublicIP() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for _, svc := range ipServices {
		ip, err := fetchPlainText(client, svc)
		if err != nil {
			lastErr = err
			continue
		}
		ip = strings.TrimSpace(ip)
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("all IP discovery services failed; last error: %w", lastErr)
}

func fetchPlainText(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
