package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	PasswordMinLen     = 15
	argonTime          = 3
	argonMemoryKiB     = 64 * 1024 // 64 MiB
	argonThreads       = 1
	argonKeyLen        = 32
	argonSaltLen       = 16
	MaxFailedLogins    = 5
	LockoutDurationMin = 15
)

var (
	ErrPasswordPolicy  = errors.New("password does not meet policy")
	ErrPasswordMismatch = errors.New("invalid credentials")
	ErrAccountLocked   = errors.New("account locked")
	ErrAccountDisabled = errors.New("account disabled")
)

// ValidatePasswordPolicy enforces SEC-AN-002 local password rules.
func ValidatePasswordPolicy(password, email string) error {
	if len(password) < PasswordMinLen {
		return fmt.Errorf("%w: minimum %d characters", ErrPasswordPolicy, PasswordMinLen)
	}
	if email != "" && strings.EqualFold(strings.TrimSpace(password), strings.TrimSpace(email)) {
		return fmt.Errorf("%w: password must not equal email", ErrPasswordPolicy)
	}
	return nil
}

// HashPassword returns a PHC-encoded Argon2id hash (m=65536, t=3, p=1).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

// VerifyPassword checks a password against a PHC Argon2id hash.
func VerifyPassword(encoded, password string) (bool, error) {
	if encoded == "" || password == "" {
		return false, ErrPasswordMismatch
	}
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrPasswordMismatch
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, ErrPasswordMismatch
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrPasswordMismatch
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrPasswordMismatch
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, nil
	}
	return true, nil
}

// GenerateTempPassword returns a random password meeting the length policy.
func GenerateTempPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
