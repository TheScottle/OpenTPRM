package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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

var (
	ErrWebAuthnInvalid   = errors.New("webauthn assertion invalid")
	ErrWebAuthnUnknown   = errors.New("webauthn credential unknown")
	ErrWebAuthnUserBound  = errors.New("webauthn credential user mismatch")
)

// Credential is a device-bound authenticator public key (SEC-AN-003 / SEC-AN-006).
// This limited path uses Ed25519 over challenge bytes (attestation ceremony deferred).
type Credential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    ed25519.PublicKey
	SignCount    uint32
	CreatedAt    time.Time
}

// CredentialStore persists WebAuthn credentials in SQLite.
type CredentialStore struct {
	db *sql.DB
}

func NewCredentialStore(db *sql.DB) *CredentialStore {
	return &CredentialStore{db: db}
}

// EnrollBegin issues an enroll challenge for a known user.
func (c *ChallengeStore) EnrollBegin(userID string, now time.Time) (*Challenge, error) {
	return c.Issue(userID, "enroll", now)
}

// EnrollFinish consumes the enroll challenge and stores the credential.
func (cs *CredentialStore) EnrollFinish(ctx context.Context, challenges *ChallengeStore, userID, challengeID string, credentialID, publicKey, signature []byte, now time.Time) (*Credential, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrWebAuthnInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(challengeID), signature) {
		return nil, ErrWebAuthnInvalid
	}
	if err := challenges.Consume(challengeID, userID, "enroll", now); err != nil {
		return nil, err
	}
	cred := &Credential{
		ID:           hex.EncodeToString(credentialID),
		UserID:       userID,
		CredentialID: append([]byte(nil), credentialID...),
		PublicKey:    ed25519.PublicKey(append([]byte(nil), publicKey...)),
		CreatedAt:    now,
	}
	_, err := cs.db.ExecContext(ctx, `INSERT INTO webauthn_credentials(id, user_id, credential_id, public_key, sign_count, created_at)
		VALUES(?,?,?,?,0,?)`,
		cred.ID, userID, cred.CredentialID, []byte(cred.PublicKey), now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// LoginBegin issues a login challenge.
func (c *ChallengeStore) LoginBegin(userID string, now time.Time) (*Challenge, error) {
	return c.Issue(userID, "login", now)
}

// StepUpBegin issues a step-up challenge.
func (c *ChallengeStore) StepUpBegin(userID string, now time.Time) (*Challenge, error) {
	return c.Issue(userID, "step_up", now)
}

// LookupByCredentialID finds a credential by raw credential id bytes.
func (cs *CredentialStore) LookupByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error) {
	var (
		id, userID, created string
		pub                 []byte
		signCount           int
		storedCredID        []byte
	)
	err := cs.db.QueryRowContext(ctx, `SELECT id, user_id, credential_id, public_key, sign_count, created_at
		FROM webauthn_credentials WHERE credential_id=?`, credentialID).
		Scan(&id, &userID, &storedCredID, &pub, &signCount, &created)
	if err == sql.ErrNoRows {
		return nil, ErrWebAuthnUnknown
	}
	if err != nil {
		return nil, err
	}
	cred := &Credential{
		ID: id, UserID: userID, CredentialID: storedCredID,
		PublicKey: ed25519.PublicKey(pub), SignCount: uint32(signCount),
	}
	cred.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return cred, nil
}

// AssertLogin verifies a signed challenge and consumes it (login or step_up).
func (cs *CredentialStore) AssertLogin(ctx context.Context, challenges *ChallengeStore, userID, purpose, challengeID string, credentialID, signature []byte, now time.Time) (*Credential, error) {
	if purpose != "login" && purpose != "step_up" {
		return nil, ErrWebAuthnInvalid
	}
	cred, err := cs.LookupByCredentialID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if cred.UserID != userID {
		return nil, ErrWebAuthnUserBound
	}
	if !ed25519.Verify(cred.PublicKey, []byte(challengeID), signature) {
		return nil, ErrWebAuthnInvalid
	}
	if err := challenges.Consume(challengeID, userID, purpose, now); err != nil {
		return nil, err
	}
	_, _ = cs.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=sign_count+1 WHERE id=?`, cred.ID)
	cred.SignCount++
	return cred, nil
}

// GenerateDeviceKeypair creates an Ed25519 keypair for tests / local enroll helpers.
func GenerateDeviceKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
