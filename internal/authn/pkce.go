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
	ErrInvalidPKCE       = errors.New("invalid PKCE code_challenge or verifier")
	ErrUnknownClient     = errors.New("client not pre-registered")
	ErrInvalidRedirect   = errors.New("redirect_uri not registered for client")
	ErrAuthCodeInvalid   = errors.New("authorization code invalid or expired")
	ErrAuthCodeUsed      = errors.New("authorization code already used")
	ErrMissingPKCE       = errors.New("PKCE S256 code_challenge required")
)

// RegisteredClient is a pre-registered OAuth client (DCR disabled; ADR-002).
type RegisteredClient struct {
	ID           string
	RedirectURIs []string
	Public       bool // public clients use PKCE; confidential may use private_key_jwt later
}

// AuthCode is a single-use authorization code bound to PKCE and a client.
type AuthCode struct {
	CodeHash      string
	ClientID      string
	UserID        string
	RedirectURI   string
	Scopes        []string
	Audience      string
	CodeChallenge string
	ChallengeMeth string
	ExpiresAt     time.Time
	Used          bool
}

// ClientRegistry holds Security-Administrator pre-registered clients.
type ClientRegistry struct {
	mu      sync.RWMutex
	clients map[string]RegisteredClient
}

// NewClientRegistry constructs an empty registry.
func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{clients: map[string]RegisteredClient{}}
}

// Register adds or replaces a pre-registered client.
func (r *ClientRegistry) Register(c RegisteredClient) error {
	if r == nil || c.ID == "" {
		return ErrUnknownClient
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := c
	cp.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	r.clients[c.ID] = cp
	return nil
}

// Get returns a registered client.
func (r *ClientRegistry) Get(id string) (RegisteredClient, error) {
	if r == nil {
		return RegisteredClient{}, ErrUnknownClient
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[id]
	if !ok {
		return RegisteredClient{}, ErrUnknownClient
	}
	return c, nil
}

// ValidateRedirect ensures redirectURI is an exact match for the client.
func (r *ClientRegistry) ValidateRedirect(clientID, redirectURI string) error {
	c, err := r.Get(clientID)
	if err != nil {
		return err
	}
	for _, u := range c.RedirectURIs {
		if u == redirectURI {
			return nil
		}
	}
	return ErrInvalidRedirect
}

// S256Challenge computes BASE64URL(SHA256(verifier)) per RFC 7636.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks code_verifier against the stored S256 challenge.
func VerifyPKCE(challenge, method, verifier string) error {
	if challenge == "" || verifier == "" {
		return ErrInvalidPKCE
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != "S256" {
		return ErrInvalidPKCE
	}
	if S256Challenge(verifier) != challenge {
		return ErrInvalidPKCE
	}
	return nil
}

// AuthCodeStore issues and consumes authorization codes (in-memory).
type AuthCodeStore struct {
	mu    sync.Mutex
	codes map[string]AuthCode
	TTL   time.Duration
}

// NewAuthCodeStore constructs a code store with the given TTL (default 10m).
func NewAuthCodeStore(ttl time.Duration) *AuthCodeStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &AuthCodeStore{codes: map[string]AuthCode{}, TTL: ttl}
}

// Issue creates a single-use authorization code for a pre-validated authorize request.
func (s *AuthCodeStore) Issue(clientID, userID, redirectURI, audience string, scopes []string, codeChallenge, method string) (plaintext string, err error) {
	if s == nil {
		return "", ErrAuthCodeInvalid
	}
	if codeChallenge == "" || strings.ToUpper(method) != "S256" {
		return "", ErrMissingPKCE
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plaintext = hex.EncodeToString(raw)
	hash := HashToken(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hash] = AuthCode{
		CodeHash: hash, ClientID: clientID, UserID: userID, RedirectURI: redirectURI,
		Scopes: append([]string(nil), scopes...), Audience: audience,
		CodeChallenge: codeChallenge, ChallengeMeth: "S256",
		ExpiresAt: time.Now().UTC().Add(s.TTL),
	}
	return plaintext, nil
}

// Consume validates PKCE, marks the code used, and returns the stored record.
func (s *AuthCodeStore) Consume(plaintext, clientID, redirectURI, codeVerifier string) (AuthCode, error) {
	if s == nil || plaintext == "" {
		return AuthCode{}, ErrAuthCodeInvalid
	}
	hash := HashToken(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[hash]
	if !ok {
		return AuthCode{}, ErrAuthCodeInvalid
	}
	if ac.Used {
		return AuthCode{}, ErrAuthCodeUsed
	}
	if time.Now().UTC().After(ac.ExpiresAt) {
		delete(s.codes, hash)
		return AuthCode{}, ErrAuthCodeInvalid
	}
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		return AuthCode{}, ErrAuthCodeInvalid
	}
	if err := VerifyPKCE(ac.CodeChallenge, ac.ChallengeMeth, codeVerifier); err != nil {
		return AuthCode{}, err
	}
	ac.Used = true
	s.codes[hash] = ac
	return ac, nil
}
