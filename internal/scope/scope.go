package scope

import (
	"net"
	"strings"
	"sync"
	"veex0x01-intel/pkg/logger"
)

// Engine enforces the boundaries of the authorized assessment
type Engine struct {
	mu            sync.RWMutex
	AllowedRoots  map[string]struct{}
	AllowedCIDRs  []*net.IPNet
	BlockedRoots  map[string]struct{}
}

// NewEngine initializes a new scope engine based on inputs
func NewEngine(targets []string) *Engine {
	e := &Engine{
		AllowedRoots: make(map[string]struct{}),
		BlockedRoots: make(map[string]struct{}),
	}
	
	for _, t := range targets {
		e.AddAllowed(t)
	}

	return e
}

// AddAllowed adds a target to the allowed scope list
func (e *Engine) AddAllowed(target string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if strings.Contains(target, "/") {
		_, ipNet, err := net.ParseCIDR(target)
		if err == nil {
			e.AllowedCIDRs = append(e.AllowedCIDRs, ipNet)
		}
	} else {
		e.AllowedRoots[target] = struct{}{}
	}
}

// IsInScope checks whether a target (IP or domain) is cleared for active/passive processing
func (e *Engine) IsInScope(target string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check explicit blocks
	if _, blocked := e.BlockedRoots[target]; blocked {
		return false
	}

	// 1. Check direct domain/subdomain match
	for root := range e.AllowedRoots {
		if strings.HasSuffix(target, root) {
			return true
		}
	}

	// 2. Check if it's an IP within our allowed CIDRs
	ip := net.ParseIP(target)
	if ip != nil {
		for _, netBlock := range e.AllowedCIDRs {
			if netBlock.Contains(ip) {
				return true
			}
		}
	}

	logger.Warn("Out of scope target discarded", map[string]interface{}{"target": target})
	return false
}

// MarkThirdParty prevents further enumeration of known out-of-scope assets (like CDNs)
func (e *Engine) MarkThirdParty(target string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.BlockedRoots[target] = struct{}{}
}
