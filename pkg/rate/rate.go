package rate

import (
	"context"
	"golang.org/x/time/rate"
)

// Limiter wraps the golang rate.Limiter
type Limiter struct {
	limiter *rate.Limiter
}

// NewLimiter creates a new rate limiter allowing 'rps' events per second
func NewLimiter(rps float64, burst int) *Limiter {
	return &Limiter{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

// Wait blocks until the next event is allowed
func (l *Limiter) Wait(ctx context.Context) error {
	return l.limiter.Wait(ctx)
}

// Allow returns true if an event is allowed immediately
func (l *Limiter) Allow() bool {
	return l.limiter.Allow()
}
