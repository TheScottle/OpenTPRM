package authn

import (
	"sync"
	"time"
)

// Throttle limits attempts per key (account or IP) — SEC-AN-006.
type Throttle struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewThrottle(limit int, window time.Duration) *Throttle {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Throttle{attempts: map[string][]time.Time{}, limit: limit, window: window}
}

// Allow records an attempt and returns ErrThrottle when over limit.
func (t *Throttle) Allow(key string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := now.Add(-t.window)
	xs := t.attempts[key]
	kept := xs[:0]
	for _, ts := range xs {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= t.limit {
		t.attempts[key] = kept
		return ErrThrottle
	}
	t.attempts[key] = append(kept, now)
	return nil
}
