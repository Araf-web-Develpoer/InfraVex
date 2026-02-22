package network

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"InfraVex/pkg/logger"
)

// IPInfo represents network intelligence for an IP
type IPInfo struct {
	IP       string `json:"ip"`
	ASN      string `json:"asn"`
	Org      string `json:"org"`
	Netblock string `json:"network"` // CIDR block
}

// GetInfo fetches WHOIS/ASN data for an IP using a public API (like ipinfo.io/ipWhois/etc.)
// In a real framework, we'd use local maxmind DB, cymru BGP lookups, or RDAP.
// Here we mock the RDAP/API call for safety and example purposes.
func GetInfo(ip string) (*IPInfo, error) {
	// Example using a public API (ipwhois.app or similar)
	// You should require an API key or use RDAP for enterprise
	url := fmt.Sprintf("http://ipwhois.app/json/%s", ip)

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Error("Failed to fetch ASN info", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		IP  string `json:"ip"`
		ASN string `json:"asn"`
		Org string `json:"org"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	info := &IPInfo{
		IP:  data.IP,
		ASN: data.ASN,
		Org: data.Org,
	}

	// Safe org matching example
	logger.Info("ASN Pivot logic check", map[string]interface{}{
		"ip": ip,
		"org": info.Org,
	})

	return info, nil
}

// MatchOrg determines if the discovered organization matches the target organization
func MatchOrg(targetOrg, discoveredOrg string) bool {
	t := strings.ToLower(strings.TrimSpace(targetOrg))
	d := strings.ToLower(strings.TrimSpace(discoveredOrg))

	if t == "" || d == "" {
		return false
	}
	
	// Basic fuzzy match
	return strings.Contains(d, t)
}
