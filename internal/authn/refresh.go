package authn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrRefreshInvalid   = errors.New("refresh token invalid or expired")
	ErrRefreshReuse     = errors.New("refresh token reuse detected; family revoked")
	ErrRefreshRevoked   = errors.New("refresh token family revoked")
	ErrNoRefreshForType = errors.New("refresh tokens not issued for this client type")
)

// RefreshTTL is the default refresh-token lifetime for delegated (human) grants.
const RefreshTTL = 30 * 24 * time.Hour

// RefreshGrant tracks a rotating refresh token family.
type RefreshGrant struct {
	FamilyID       string
	ClientID       string
	UserID         string
	Scopes         []string
	Audience       string
	DPoPThumbprint string
	CurrentHash    string
	ExpiresAt      time.Time
	Revoked        bool
}

// RefreshStore issues rotating refresh tokens with reuse detection (RFC 9700 style).
type RefreshStore struct {
	mu      sync.Mutex
	byHash  map[string]*RefreshGrant // current + previously rotated hashes → family
	family  map[string]*RefreshGrant // familyID → grant
	TTL     time.Duration
}

// NewRefreshStore constructs an in-memory rotating refresh store.
func NewRefreshStore(ttl time.Duration) *RefreshStore {
	if ttl <= 0 {
		ttl = RefreshTTL
	}
	return &RefreshStore{
		byHash: map[string]*RefreshGrant{},
		family: map[string]*RefreshGrant{},
		TTL:    ttl,
	}
}

// Issue creates a new refresh-token family and returns the plaintext refresh token once.
func (s *RefreshStore) Issue(clientID, userID, audience, dpopThumb string, scopes []string) (plaintext string, grant RefreshGrant, err error) {
	if s == nil {
		return "", RefreshGrant{}, ErrRefreshInvalid
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", RefreshGrant{}, err
	}
	plaintext = hex.EncodeToString(raw)
	hash := HashToken(plaintext)
	famRaw := make([]byte, 16)
	if _, err := rand.Read(famRaw); err != nil {
		return "", RefreshGrant{}, err
	}
	familyID := hex.EncodeToString(famRaw)
	g := &RefreshGrant{
		FamilyID: familyID, ClientID: clientID, UserID: userID,
		Scopes: append([]string(nil), scopes...), Audience: audience,
		DPoPThumbprint: dpopThumb, CurrentHash: hash,
		ExpiresAt: time.Now().UTC().Add(s.TTL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.family[familyID] = g
	s.byHash[hash] = g
	return plaintext, *g, nil
}

// Rotate validates the presented refresh token, issues a new one, and detects reuse.
// On reuse of a prior (non-current) token in the family, the entire family is revoked.
func (s *RefreshStore) Rotate(plaintext string) (newPlaintext string, grant RefreshGrant, err error) {
	if s == nil || strings.TrimSpace(plaintext) == "" {
		return "", RefreshGrant{}, ErrRefreshInvalid
	}
	hash := HashToken(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byHash[hash]
	if !ok || g == nil {
		return "", RefreshGrant{}, ErrRefreshInvalid
	}
	if g.Revoked {
		return "", RefreshGrant{}, ErrRefreshRevoked
	}
	if time.Now().UTC().After(g.ExpiresAt) {
		return "", RefreshGrant{}, ErrRefreshInvalid
	}
	if g.CurrentHash != hash {
		// Reuse of a rotated token → revoke family (RFC 9700).
		g.Revoked = true
		return "", RefreshGrant{}, ErrRefreshReuse
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", RefreshGrant{}, err
	}
	newPlaintext = hex.EncodeToString(raw)
	newHash := HashToken(newPlaintext)
	// Keep old hash mapped so reuse can be detected.
	g.CurrentHash = newHash
	g.ExpiresAt = time.Now().UTC().Add(s.TTL)
	s.byHash[newHash] = g
	return newPlaintext, *g, nil
}

// RevokeFamily marks a refresh family revoked.
func (s *RefreshStore) RevokeFamily(familyID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.family[familyID]; ok {
		g.Revoked = true
	}
}
