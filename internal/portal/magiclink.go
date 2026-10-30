package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrMagicLinkInvalid = errors.New("magic link invalid or expired")
	ErrMagicLinkUsed    = errors.New("magic link already consumed")
)

// MagicLink is a single-use portal login token (POR-002 stub).
type MagicLink struct {
	TokenHash string
	VendorID  string
	Email     string
	ExpiresAt time.Time
	Used      bool
}

// MagicLinkStore issues and consumes hashed magic-link tokens.
type MagicLinkStore struct {
	mu     sync.Mutex
	tokens map[string]MagicLink
	TTL    time.Duration
}

// NewMagicLinkStore constructs an in-memory magic-link store (default TTL 15m).
func NewMagicLinkStore(ttl time.Duration) *MagicLinkStore {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &MagicLinkStore{tokens: map[string]MagicLink{}, TTL: ttl}
}

func hashMagic(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue creates a plaintext magic-link token bound to vendorID + email.
func (s *MagicLinkStore) Issue(vendorID, email string) (plaintext string, err error) {
	if s == nil || vendorID == "" || email == "" {
		return "", ErrMagicLinkInvalid
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plaintext = hex.EncodeToString(raw)
	hash := hashMagic(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hash] = MagicLink{
		TokenHash: hash, VendorID: vendorID, Email: email,
		ExpiresAt: time.Now().UTC().Add(s.TTL),
	}
	return plaintext, nil
}

// Consume validates and single-uses a magic-link token.
func (s *MagicLinkStore) Consume(plaintext string) (MagicLink, error) {
	if s == nil || plaintext == "" {
		return MagicLink{}, ErrMagicLinkInvalid
	}
	hash := hashMagic(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	ml, ok := s.tokens[hash]
	if !ok {
		return MagicLink{}, ErrMagicLinkInvalid
	}
	if ml.Used {
		return MagicLink{}, ErrMagicLinkUsed
	}
	if time.Now().UTC().After(ml.ExpiresAt) {
		delete(s.tokens, hash)
		return MagicLink{}, ErrMagicLinkInvalid
	}
	ml.Used = true
	s.tokens[hash] = ml
	return ml, nil
}
