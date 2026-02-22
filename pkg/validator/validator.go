package validator

import (
	"net"
	"regexp"
	"strings"
)

// DomainRegex roughly validates a domain name structure
var DomainRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)

// IsValidDomain checks if the provided string is a structurally valid domain
func IsValidDomain(domain string) bool {
	return DomainRegex.MatchString(domain)
}

// IsValidIP checks if the provided string is a valid IPv4 or IPv6 address.
func IsValidIP(ipStr string) bool {
	return net.ParseIP(ipStr) != nil
}

// IsValidCIDR checks if the provided string is a valid CIDR block.
func IsValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}

// EnsureHTTPS prepends https:// if missing
func EnsureHTTPS(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
}
