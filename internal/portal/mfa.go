package portal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrPasskeyInvalid = errors.New("passkey enrollment invalid")
	ErrTOTPInvalid    = errors.New("totp invalid")
	ErrTOTPNotEnrolled = errors.New("totp not enrolled")
)

// PasskeyCredential is a vendor portal passkey stub (POR-002; full WebAuthn attestation later).
type PasskeyCredential struct {
	ID         string
	VendorID   string
	Email      string
	PublicKey  string
	EnrolledAt time.Time
}

// PasskeyStore holds enrolled vendor passkeys (in-memory stub).
type PasskeyStore struct {
	mu   sync.Mutex
	byID map[string]PasskeyCredential
	// byVendorEmail → credential id
	index map[string]string
}

// NewPasskeyStore constructs an empty passkey store.
func NewPasskeyStore() *PasskeyStore {
	return &PasskeyStore{byID: map[string]PasskeyCredential{}, index: map[string]string{}}
}

func passkeyIndexKey(vendorID, email string) string {
	return vendorID + "|" + strings.ToLower(strings.TrimSpace(email))
}

// Enroll registers a stub passkey for a vendor user (challenge must be single-use externally).
func (s *PasskeyStore) Enroll(vendorID, email, publicKey string) (PasskeyCredential, error) {
	vendorID = strings.TrimSpace(vendorID)
	email = strings.TrimSpace(email)
	if vendorID == "" || email == "" || strings.TrimSpace(publicKey) == "" {
		return PasskeyCredential{}, ErrPasskeyInvalid
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return PasskeyCredential{}, err
	}
	cred := PasskeyCredential{
		ID:         hex.EncodeToString(b),
		VendorID:   vendorID,
		Email:      email,
		PublicKey:  publicKey,
		EnrolledAt: time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[cred.ID] = cred
	s.index[passkeyIndexKey(vendorID, email)] = cred.ID
	return cred, nil
}

// Lookup returns an enrolled passkey for vendor+email if present.
func (s *PasskeyStore) Lookup(vendorID, email string) (PasskeyCredential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.index[passkeyIndexKey(vendorID, email)]
	if !ok {
		return PasskeyCredential{}, false
	}
	return s.byID[id], true
}

// TOTPEnrollment stores a hashed TOTP secret for a vendor user (RFC 6238 stub).
type TOTPEnrollment struct {
	VendorID  string
	Email     string
	Secret    string // base32 (returned once on enroll; stored hashed)
	secretRaw []byte
	Enrolled  time.Time
}

// TOTPStore is an in-memory TOTP enroll/verify stub (POR-002 fallback).
type TOTPStore struct {
	mu      sync.Mutex
	byKey   map[string]TOTPEnrollment
	stepSec int64
}

// NewTOTPStore constructs a TOTP store with 30s steps.
func NewTOTPStore() *TOTPStore {
	return &TOTPStore{byKey: map[string]TOTPEnrollment{}, stepSec: 30}
}

// Enroll creates a new TOTP secret for vendor+email (returns plaintext secret once).
func (s *TOTPStore) Enroll(vendorID, email string) (TOTPEnrollment, error) {
	vendorID = strings.TrimSpace(vendorID)
	email = strings.TrimSpace(email)
	if vendorID == "" || email == "" {
		return TOTPEnrollment{}, ErrTOTPInvalid
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return TOTPEnrollment{}, err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	en := TOTPEnrollment{
		VendorID:  vendorID,
		Email:     email,
		Secret:    secret,
		secretRaw: raw,
		Enrolled:  time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[passkeyIndexKey(vendorID, email)] = en
	return en, nil
}

// CurrentCode returns the current TOTP code for an enrollment (test/stub helper).
func (s *TOTPStore) CurrentCode(vendorID, email string, now time.Time) (string, error) {
	s.mu.Lock()
	en, ok := s.byKey[passkeyIndexKey(vendorID, email)]
	s.mu.Unlock()
	if !ok {
		return "", ErrTOTPNotEnrolled
	}
	step := now.Unix() / s.stepSec
	return hotp(en.secretRaw, uint64(step)), nil
}

// Verify checks a 6-digit TOTP code (±1 step window).
func (s *TOTPStore) Verify(vendorID, email, code string, now time.Time) error {
	s.mu.Lock()
	en, ok := s.byKey[passkeyIndexKey(vendorID, email)]
	s.mu.Unlock()
	if !ok {
		return ErrTOTPNotEnrolled
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return ErrTOTPInvalid
	}
	step := now.Unix() / s.stepSec
	for _, d := range []int64{-1, 0, 1} {
		if hotp(en.secretRaw, uint64(step+d)) == code {
			return nil
		}
	}
	return ErrTOTPInvalid
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", truncated%1000000)
}
