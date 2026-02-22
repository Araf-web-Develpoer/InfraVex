package intelligence

import (
	"context"
	"net"
	"strings"

	"veex0x01-intel/pkg/logger"
)

// ReverseLookup performs a DNS PTR record lookup for an IP
func ReverseLookup(ctx context.Context, ip string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
	}

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Clean trailing dots
	var cleanNames []string
	for _, name := range names {
		cleanNames = append(cleanNames, strings.TrimSuffix(name, "."))
	}

	if len(cleanNames) > 0 {
		logger.Info("Reverse DNS success", map[string]interface{}{"ip": ip, "names": cleanNames})
	}

	return cleanNames, nil
}
