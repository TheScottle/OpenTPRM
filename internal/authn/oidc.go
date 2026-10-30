package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrOIDCInvalidIssuer   = errors.New("oidc: issuer mismatch")
	ErrOIDCInvalidAudience = errors.New("oidc: audience mismatch")
	ErrOIDCExpired         = errors.New("oidc: token expired")
	ErrOIDCNonce           = errors.New("oidc: nonce mismatch")
	ErrOIDCMFARequired     = errors.New("oidc: MFA evidence required")
)

// OIDCConfig holds workforce SSO settings (SEC-AN-001). No secrets in env.
type OIDCConfig struct {
	Issuer            string
	ClientID          string
	RedirectURI       string
	RequiredACR       []string // acceptable acr values evidencing MFA
	RequiredAMR       []string // acceptable amr values evidencing MFA
	AllowAMRSubstring bool
}

// IDTokenClaims is the validated claim set (unit-tested without network).
type IDTokenClaims struct {
	Iss   string
	Aud   []string
	Exp   time.Time
	Nonce string
	Sub   string
	ACR   string
	AMR   []string
	Email string
}

// ValidateIDTokenClaims enforces iss/aud/exp/nonce and MFA evidence (SEC-AN-001).
// Implicit flow is never used; this validates authorization-code+PKCE results only.
func ValidateIDTokenClaims(cfg OIDCConfig, c IDTokenClaims, expectedNonce string, now time.Time) error {
	if cfg.Issuer == "" || c.Iss != cfg.Issuer {
		return ErrOIDCInvalidIssuer
	}
	if !audienceContains(c.Aud, cfg.ClientID) {
		return ErrOIDCInvalidAudience
	}
	if now.After(c.Exp) {
		return ErrOIDCExpired
	}
	if expectedNonce == "" || c.Nonce != expectedNonce {
		return ErrOIDCNonce
	}
	if !mfaEvidence(cfg, c) {
		return ErrOIDCMFARequired
	}
	return nil
}

func audienceContains(aud []string, clientID string) bool {
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}

func mfaEvidence(cfg OIDCConfig, c IDTokenClaims) bool {
	for _, want := range cfg.RequiredACR {
		if c.ACR == want {
			return true
		}
	}
	for _, want := range cfg.RequiredAMR {
		for _, got := range c.AMR {
			if got == want || (cfg.AllowAMRSubstring && strings.Contains(got, want)) {
				return true
			}
		}
	}
	// If no MFA requirements configured, accept (dev); production config must set them.
	return len(cfg.RequiredACR) == 0 && len(cfg.RequiredAMR) == 0
}

// PKCEVerifier generates S256 PKCE verifier/challenge pair.
func PKCEVerifier() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// AuthStateStore holds short-lived OIDC state+nonce handles (sealed in production).
type AuthStateStore struct {
	mu    sync.Mutex
	items map[string]authState
}

type authState struct {
	Nonce     string
	Verifier  string
	ExpiresAt time.Time
}

func NewAuthStateStore() *AuthStateStore {
	return &AuthStateStore{items: map[string]authState{}}
}

func (s *AuthStateStore) Put(nonce, verifier string, now time.Time) (stateID string, err error) {
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	stateID = hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[stateID] = authState{Nonce: nonce, Verifier: verifier, ExpiresAt: now.Add(ChallengeTTL)}
	return stateID, nil
}

func (s *AuthStateStore) Take(stateID string, now time.Time) (nonce, verifier string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, exists := s.items[stateID]
	if !exists || now.After(st.ExpiresAt) {
		delete(s.items, stateID)
		return "", "", false
	}
	delete(s.items, stateID)
	return st.Nonce, st.Verifier, true
}
