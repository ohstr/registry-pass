package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiter is a set of token buckets, one per key. It holds at most
// maxKeys buckets: idle ones are swept first, and if that isn't enough the
// set is reset, so a flood of distinct keys can't exhaust memory.
type limiter struct {
	limit   rate.Limit
	burst   int
	maxKeys int
	idle    time.Duration
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// newLimiter returns nil (no limit) when perSecond is 0.
func newLimiter(perSecond float64, burst, maxKeys int) *limiter {
	if perSecond <= 0 {
		return nil
	}
	return &limiter{
		limit: rate.Limit(perSecond), burst: burst, maxKeys: maxKeys,
		idle: 10 * time.Minute, now: time.Now, buckets: map[string]*bucket{},
	}
}

// allow takes one token for key. A nil limiter allows everything.
func (l *limiter) allow(key string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweep(now)
		}
		b = &bucket{lim: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// peek reports whether key has a token left, without taking one.
func (l *limiter) peek(key string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return true
	}
	return b.lim.TokensAt(now) >= 1
}

func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.seen) > l.idle {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		l.buckets = map[string]*bucket{}
	}
}
