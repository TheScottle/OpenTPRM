package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Key sizes
const (
	MasterKeySize = 32
	XTSKeySize    = 64 // AES-256-XTS
	AEADKeySize   = 32
)

var (
	ErrSealed       = errors.New("keyring sealed: master key unavailable")
	ErrWeakMaster   = errors.New("master key must be 32 bytes")
	ErrAlreadyOpen  = errors.New("keyring already unsealed")
)

// Keyring holds derived KEKs. Without a master key the process stays sealed (SEC-KM-001).
type Keyring struct {
	mu sync.RWMutex

	sealed bool

	master []byte

	DBKey          []byte // 64-byte XTS key
	FieldKEK       []byte
	BlobKEK        []byte
	TokenPepper    []byte
	CookieKey      []byte
	CSRFKey        []byte
	StateHandleKey []byte
	SigningPriv    ed25519.PrivateKey
	SigningPub     ed25519.PublicKey
}

// NewSealed returns a sealed keyring (no data access).
func NewSealed() *Keyring {
	return &Keyring{sealed: true}
}

// UnsealFromFile loads a 32-byte master key from path (mode should be 0400/0600).
func (k *Keyring) UnsealFromFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read master key: %w", err)
	}
	// Accept raw 32 bytes or 64 hex chars.
	key, err := normalizeMaster(b)
	if err != nil {
		return err
	}
	return k.Unseal(key)
}

// UnsealFromPassphrase derives a master key with Argon2id.
func (k *Keyring) UnsealFromPassphrase(passphrase, salt []byte) error {
	if len(salt) < 16 {
		return errors.New("salt must be at least 16 bytes")
	}
	key := argon2.IDKey(passphrase, salt, 3, 64*1024, 1, MasterKeySize)
	return k.Unseal(key)
}

// Unseal derives KEKs from a 32-byte master key.
func (k *Keyring) Unseal(master []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.sealed && len(k.master) > 0 {
		return ErrAlreadyOpen
	}
	if len(master) != MasterKeySize {
		return ErrWeakMaster
	}
	m := make([]byte, MasterKeySize)
	copy(m, master)

	k.master = m
	k.DBKey = derive(m, "opentprm/db-xts", XTSKeySize)
	k.FieldKEK = derive(m, "opentprm/field-kek", AEADKeySize)
	k.BlobKEK = derive(m, "opentprm/blob-kek", AEADKeySize)
	k.TokenPepper = derive(m, "opentprm/token-pepper", AEADKeySize)
	k.CookieKey = derive(m, "opentprm/cookie", AEADKeySize)
	k.CSRFKey = derive(m, "opentprm/csrf", AEADKeySize)
	k.StateHandleKey = derive(m, "opentprm/state-handle", AEADKeySize)

	seed := derive(m, "opentprm/ed25519-seed", ed25519.SeedSize)
	k.SigningPriv = ed25519.NewKeyFromSeed(seed)
	k.SigningPub = k.SigningPriv.Public().(ed25519.PublicKey)
	k.sealed = false
	return nil
}

// Sealed reports whether data operations must be refused.
func (k *Keyring) Sealed() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.sealed
}

// DBHexKey returns the XTS key as hex for PRAGMA hexkey (caller must not log it).
func (k *Keyring) DBHexKey() (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.sealed {
		return "", ErrSealed
	}
	return hex.EncodeToString(k.DBKey), nil
}

// SignEd25519 signs a message with the signing key.
func (k *Keyring) SignEd25519(msg []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.sealed {
		return nil, ErrSealed
	}
	return ed25519.Sign(k.SigningPriv, msg), nil
}

// VerifyEd25519 verifies a signature.
func (k *Keyring) VerifyEd25519(msg, sig []byte) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.sealed {
		return false
	}
	return ed25519.Verify(k.SigningPub, msg, sig)
}

// ZeroBestEffort clears key material from memory (best-effort).
func (k *Keyring) ZeroBestEffort() {
	k.mu.Lock()
	defer k.mu.Unlock()
	zero(k.master)
	zero(k.DBKey)
	zero(k.FieldKEK)
	zero(k.BlobKEK)
	zero(k.TokenPepper)
	zero(k.CookieKey)
	zero(k.CSRFKey)
	zero(k.StateHandleKey)
	zero(k.SigningPriv)
	k.sealed = true
}

// GenerateMasterKey writes a new 32-byte master key to path with mode 0400.
func GenerateMasterKey(path string) error {
	key := make([]byte, MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	if err := os.WriteFile(path, key, 0o400); err != nil {
		return err
	}
	return nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// HashToken returns a hex SHA-256 of pepper||token for storage.
func (k *Keyring) HashToken(token string) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.sealed {
		return "", ErrSealed
	}
	h := sha256.New()
	h.Write(k.TokenPepper)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func derive(master []byte, info string, n int) []byte {
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, n)
	_, _ = io.ReadFull(r, out)
	return out
}

func normalizeMaster(b []byte) ([]byte, error) {
	// trim trailing newlines from file
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	if len(b) == MasterKeySize {
		out := make([]byte, MasterKeySize)
		copy(out, b)
		return out, nil
	}
	if len(b) == MasterKeySize*2 {
		out := make([]byte, MasterKeySize)
		_, err := hex.Decode(out, b)
		if err != nil {
			return nil, ErrWeakMaster
		}
		return out, nil
	}
	return nil, ErrWeakMaster
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
