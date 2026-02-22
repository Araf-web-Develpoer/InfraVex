package enumeration

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"InfraVex/pkg/dedup"
	"InfraVex/pkg/logger"
	"InfraVex/pkg/rate"
)

// ExpandCIDR safely expands a CIDR block into a list of usable IP strings.
// It excludes the network broadcast and zero addresses.
func ExpandCIDR(ctx context.Context, cidr string, maxExpansion int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	limit := 1 << uint(hostBits)

	// Max expansion safety ceiling
	if hostBits > (32 - maxExpansion) { // e.g: /22 (10 bits)
		logger.Warn("CIDR too large. Denied expansion without explicit override", map[string]interface{}{
			"cidr": cidr,
			"size": fmt.Sprintf("/%d", ones),
		})
		return nil, fmt.Errorf("CIDR exceeds configured maximum expansion threshold (/%d)", maxExpansion)
	}

	var ips []string
	ipInt := binary.BigEndian.Uint32(ip.To4())

	// Exclude network address and broadcast
	for i := 1; i < limit-1; i++ {
		select {
		case <-ctx.Done():
			return ips, ctx.Err()
		default:
			ipToFormat := make(net.IP, 4)
			binary.BigEndian.PutUint32(ipToFormat, ipInt+uint32(i))
			ips = append(ips, ipToFormat.String())
		}
	}

	return ips, nil
}

// WorkerPool processes a list of targets concurrently with rate limits
func WorkerPool(
	ctx context.Context,
	targets []string,
	workerCount int,
	limiter *rate.Limiter,
	dedupStore *dedup.Store,
	workerFunc func(context.Context, string) error,
) {
	var wg sync.WaitGroup
	jobChan := make(chan string, len(targets))

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-jobChan:
					if !ok {
						return
					}
					// Only process unique targets
					if !dedupStore.IsDuplicate(t) {
						if err := limiter.Wait(ctx); err == nil {
							workerFunc(ctx, t)
						}
					}
				}
			}
		}(i)
	}

	// Feed jobs
	for _, t := range targets {
		jobChan <- t
	}
	close(jobChan)

	wg.Wait()
}
