package portal

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a basic token-bucket style limit per key (POR-005 / SEC-DOS-003 stub).
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	Limit    int
	Window   time.Duration
	now      func() time.Time
}

type bucket struct {
	count int
	reset time.Time
}

// NewRateLimiter constructs a limiter (default 10 events / minute).
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		buckets: map[string]*bucket{},
		Limit:   limit,
		Window:  window,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Allow reports whether key may proceed and records the attempt when allowed.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return true
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok || now.After(b.reset) {
		r.buckets[key] = &bucket{count: 1, reset: now.Add(r.Window)}
		return true
	}
	if b.count >= r.Limit {
		return false
	}
	b.count++
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// honeypotTriggered is true when bots fill the hidden website field.
func honeypotTriggered(r *http.Request) bool {
	v := strings.TrimSpace(r.FormValue("website"))
	return v != ""
}
