package authn

import (
	"errors"
	"sync"
	"time"
)

const BreakGlassTTL = 60 * time.Minute

var ErrBreakGlassInvalid = errors.New("break-glass request invalid")

// BreakGlassGrant is a time-boxed emergency access (SOD-8 / IAM).
type BreakGlassGrant struct {
	ID        string
	UserID    string
	Reason    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Alerted   bool
}

// BreakGlassRegistry tracks active grants. Alerts to Security Administrators are
// recorded as Alerted=true; callers must emit audit + notification events.
type BreakGlassRegistry struct {
	mu     sync.Mutex
	grants map[string]*BreakGlassGrant
}

func NewBreakGlassRegistry() *BreakGlassRegistry {
	return &BreakGlassRegistry{grants: map[string]*BreakGlassGrant{}}
}

// Grant creates a 60-minute break-glass access that requires a non-empty reason and prior step-up.
func (r *BreakGlassRegistry) Grant(id, userID, reason string, stepUpFresh bool, now time.Time) (*BreakGlassGrant, error) {
	if reason == "" || !stepUpFresh || userID == "" {
		return nil, ErrBreakGlassInvalid
	}
	g := &BreakGlassGrant{
		ID:        id,
		UserID:    userID,
		Reason:    reason,
		CreatedAt: now,
		ExpiresAt: now.Add(BreakGlassTTL),
		Alerted:   true, // SOD-8: must alert every Security Administrator
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grants[id] = g
	return g, nil
}

// Active reports whether the user currently holds a non-expired grant.
func (r *BreakGlassRegistry) Active(userID string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, g := range r.grants {
		if now.After(g.ExpiresAt) {
			delete(r.grants, id)
			continue
		}
		if g.UserID == userID {
			return true
		}
	}
	return false
}
