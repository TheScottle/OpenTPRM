package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const (
	SessionCookie = "__Host-otp_s"
	CSRFHeader    = "X-CSRF-Token"
	CSRFFormField = "csrf_token"

	IdleTimeout     = 30 * time.Minute
	AbsoluteTimeout = 12 * time.Hour
	StepUpWindow    = 5 * time.Minute
	ChallengeTTL    = 5 * time.Minute
)

var (
	ErrInvalidSession   = errors.New("invalid session")
	ErrSessionExpired   = errors.New("session expired")
	ErrSessionRevoked   = errors.New("session revoked")
	ErrCSRFMismatch     = errors.New("csrf mismatch")
	ErrChallengeExpired = errors.New("challenge expired or reused")
	ErrBootstrapUsed    = errors.New("bootstrap token already used or expired")
	ErrThrottle         = errors.New("throttled")
)

// Session is a server-side session (SEC-AN-004).
type Session struct {
	ID         string
	IDHash     string
	UserID     string
	CreatedAt  time.Time
	LastSeen   time.Time
	Absolute   time.Time
	AAL        int
	CSRFToken  string // plaintext only in memory; store hashes CSRFHash
	CSRFHash   string
	Revoked    bool
	StepUpAt   time.Time
	BreakGlass bool
	Roles      []string
	Email      string
}

// NewSessionID returns a 256-bit session id and its hash.
func NewSessionID() (id, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b)
	hash = HashToken(id)
	return id, hash, nil
}

// NewCSRFToken returns a synchronizer token and its hash (SEC-WEB CSRF).
func NewCSRFToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b)
	hash = HashToken(token)
	return token, hash, nil
}

// SetSessionCookie sets the __Host- cookie attributes (SEC-AN-004).
func SetSessionCookie(w http.ResponseWriter, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie clears the session cookie.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// HashToken hashes an opaque token for storage (never store raw session IDs).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeMatch compares two hex hashes.
func ConstantTimeMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateCSRF checks the synchronizer token against the session hash.
func ValidateCSRF(sess *Session, presented string) error {
	if sess == nil || presented == "" || sess.CSRFHash == "" {
		return ErrCSRFMismatch
	}
	if !ConstantTimeMatch(HashToken(presented), sess.CSRFHash) {
		return ErrCSRFMismatch
	}
	return nil
}

// Alive reports whether the session is within idle and absolute windows.
func (s *Session) Alive(now time.Time) error {
	if s == nil {
		return ErrInvalidSession
	}
	if s.Revoked {
		return ErrSessionRevoked
	}
	if now.After(s.Absolute) {
		return ErrSessionExpired
	}
	if now.Sub(s.LastSeen) > IdleTimeout {
		return ErrSessionExpired
	}
	return nil
}

// StepUpFresh reports WebAuthn step-up within the last 5 minutes (SEC-AN-003).
func (s *Session) StepUpFresh(now time.Time) bool {
	if s == nil || s.StepUpAt.IsZero() {
		return false
	}
	return now.Sub(s.StepUpAt) <= StepUpWindow
}
