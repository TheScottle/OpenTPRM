package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const SessionCookie = "__Host-otp_s"

var ErrInvalidSession = errors.New("invalid session")

// Session is a server-side session (SEC-AN-004).
type Session struct {
	ID        string
	IDHash    string
	UserID    string
	CreatedAt time.Time
	LastSeen  time.Time
	Absolute  time.Time
	AAL       int
	CSRFHash  string
	Revoked   bool
}

// NewSessionID returns a 256-bit session id and its hash.
func NewSessionID() (id, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	id = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(id))
	hash = hex.EncodeToString(sum[:])
	return id, hash, nil
}

// SetSessionCookie sets the __Host- cookie attributes.
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

// HashToken hashes an opaque token for storage.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
