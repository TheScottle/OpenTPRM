package authn

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Challenge is a single-use WebAuthn challenge (SEC-AN-006).
type Challenge struct {
	ID        string
	UserID    string
	Purpose   string // "login" | "step_up" | "enroll"
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

// ChallengeStore is an in-memory single-use challenge registry.
type ChallengeStore struct {
	mu   sync.Mutex
	byID map[string]*Challenge
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{byID: map[string]*Challenge{}}
}

// Issue creates a single-use challenge with 5-minute TTL.
func (c *ChallengeStore) Issue(userID, purpose string, now time.Time) (*Challenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ch := &Challenge{
		ID:        hex.EncodeToString(b),
		UserID:    userID,
		Purpose:   purpose,
		CreatedAt: now,
		ExpiresAt: now.Add(ChallengeTTL),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)
	c.byID[ch.ID] = ch
	return ch, nil
}

// Consume validates and marks a challenge used. Returns ErrChallengeExpired on reuse/expiry.
func (c *ChallengeStore) Consume(id, userID, purpose string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.byID[id]
	if !ok || ch.Used || now.After(ch.ExpiresAt) {
		return ErrChallengeExpired
	}
	if ch.UserID != userID || ch.Purpose != purpose {
		return ErrChallengeExpired
	}
	ch.Used = true
	delete(c.byID, id)
	return nil
}

func (c *ChallengeStore) gcLocked(now time.Time) {
	for id, ch := range c.byID {
		if ch.Used || now.After(ch.ExpiresAt) {
			delete(c.byID, id)
		}
	}
}
