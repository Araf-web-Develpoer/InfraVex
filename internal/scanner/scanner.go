package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"veex0x01-intel/pkg/logger"
)

// ActiveScan represents a controlled active TCP scan against explicit targets
type ActiveScan struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
}

// NewActiveScan initializes the scanner with top ports explicitly defined
func NewActiveScan(ports []int, timeoutSeconds int, maxWorkers int) *ActiveScan {
	if maxWorkers <= 0 {
		maxWorkers = 50 // Default safe cap
	}
	return &ActiveScan{
		Ports:       ports,
		Timeout:     time.Duration(timeoutSeconds) * time.Second,
		Concurrency: maxWorkers,
	}
}

// ScanTargets executes quick TCP checks, yielding an open port list per IP
func (s *ActiveScan) ScanTargets(ctx context.Context, ip string) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, s.Concurrency)

	for _, port := range s.Ports {
		select {
		case <-ctx.Done():
			logger.Warn("Context cancelled during active scan", map[string]interface{}{"ip": ip})
			return openPorts
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{} // Acquire

		go func(p int) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release

			if s.checkPort(ip, p) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	if len(openPorts) > 0 {
		logger.Info("Active scan found open ports", map[string]interface{}{
			"ip":    ip,
			"ports": openPorts,
		})
	}
	return openPorts
}

// checkPort performs a very fast, single TCP dial probe
func (s *ActiveScan) checkPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, s.Timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}

// Fingerprint grabs application layer banners based on established TCP connections
// This forms Phase 2 of the Active module. (Basic skeleton)
func (s *ActiveScan) Fingerprint(ctx context.Context, ip string, port int) string {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, s.Timeout*2)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	
	var banner string
	if port == 80 || port == 443 || port == 8080 {
		// Minimum safe HTTP req for banner/Title grabbing
		req := "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: veex0x01-intel/1.0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(req))
		
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil {
			banner = string(buf[:n])
		}
	} else {
		// Generic banner grab mapping (SSH, FTP)
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err == nil {
			banner = string(buf[:n])
		}
	}

	return banner
}
