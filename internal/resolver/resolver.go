package resolver

import (
	"context"
	"net"
	"strings"
	"time"

	"veex0x01-intel/pkg/logger"
)

// Record holds the DNS resolution results
type Record struct {
	Domain   string
	IPs      []string
	CNAME    string
	IsCloud  bool
	Provider string
}

var knownCDNs = map[string]string{
	"cloudflare": "Cloudflare",
	"aws":        "AWS",
	"amazon":     "AWS",
	"azure":      "Azure",
	"fastly":     "Fastly",
	"akamai":     "Akamai",
	"digitalocean": "DigitalOcean",
}

// Resolve performs A, AAAA, and CNAME lookups and detects Cloud/CDNs
func Resolve(ctx context.Context, domain string) (*Record, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000), // 10s default
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	rec := &Record{Domain: domain}

	// Resolve CNAME
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err == nil && cname != domain+"." {
		rec.CNAME = strings.TrimSuffix(cname, ".")
		rec.IsCloud, rec.Provider = detectCloud(rec.CNAME)
	}

	// Resolve IPs (A and AAAA)
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		logger.Warn("Failed to resolve IP", map[string]interface{}{"domain": domain, "error": err.Error()})
		return rec, err
	}

	for _, ip := range ips {
		rec.IPs = append(rec.IPs, ip.IP.String())
	}

	return rec, nil
}

// detectCloud checks if the CNAME matches known cloud or CDN providers
func detectCloud(cname string) (bool, string) {
	cnameLower := strings.ToLower(cname)
	for trigger, provider := range knownCDNs {
		if strings.Contains(cnameLower, trigger) {
			return true, provider
		}
	}
	return false, ""
}
