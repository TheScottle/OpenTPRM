package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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
	ErrWebAuthnInvalid  = errors.New("webauthn assertion invalid")
	ErrWebAuthnUnknown  = errors.New("webauthn credential unknown")
	ErrWebAuthnUserBound = errors.New("webauthn credential user mismatch")
)

// Credential is a device-bound authenticator public key (SEC-AN-003 / SEC-AN-006).
// Raw Ed25519 remains supported; COSE public keys are preferred when present.
type Credential struct {
	ID                string
	UserID            string
	CredentialID      []byte
	PublicKey         ed25519.PublicKey
	PublicKeyCOSE     []byte
	PublicKeyAlg      int64
	AAGUID            []byte
	Transports        []string
	AttestationFormat string
	Nickname          string
	SignCount         uint32
	CreatedAt         time.Time
}

// EnrollInput carries enroll/finish credential material from the client body.
type EnrollInput struct {
	CredentialID      []byte
	PublicKey         []byte // raw Ed25519 (32) when no COSE
	PublicKeyCOSE     []byte // preferred COSE_Key
	PublicKeyAlg      int64
	AAGUID            []byte
	Transports        []string
	AttestationFormat string
	Nickname          string
	Signature         []byte
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

// EnrollFinish consumes the enroll challenge and stores the credential (raw + optional COSE).
func (cs *CredentialStore) EnrollFinish(ctx context.Context, challenges *ChallengeStore, userID, challengeID string, credentialID, publicKey, signature []byte, now time.Time) (*Credential, error) {
	return cs.EnrollFinishRich(ctx, challenges, userID, challengeID, EnrollInput{
		CredentialID: credentialID,
		PublicKey:    publicKey,
		Signature:    signature,
	}, now)
}

// EnrollFinishRich stores a more complete credential public key from the enroll body.
func (cs *CredentialStore) EnrollFinishRich(ctx context.Context, challenges *ChallengeStore, userID, challengeID string, in EnrollInput, now time.Time) (*Credential, error) {
	pub := in.PublicKey
	cose := append([]byte(nil), in.PublicKeyCOSE...)
	alg := in.PublicKeyAlg

	if len(cose) > 0 {
		key, err := webauthncose.ParsePublicKey(cose)
		if err != nil {
			return nil, ErrWebAuthnInvalid
		}
		ok, err := webauthncose.VerifySignature(key, []byte(challengeID), in.Signature)
		if err != nil || !ok {
			return nil, ErrWebAuthnInvalid
		}
		if alg == 0 {
			alg = coseAlg(key)
		}
		if raw := okpRawEd25519(key); len(raw) == ed25519.PublicKeySize {
			pub = raw
		}
	} else {
		if len(pub) != ed25519.PublicKeySize {
			return nil, ErrWebAuthnInvalid
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), []byte(challengeID), in.Signature) {
			return nil, ErrWebAuthnInvalid
		}
		// Synthesize COSE OKP Ed25519 so later assertions can use webauthncose.
		var err error
		cose, err = MarshalEd25519COSE(ed25519.PublicKey(pub))
		if err != nil {
			return nil, err
		}
		if alg == 0 {
			alg = int64(webauthncose.AlgEdDSA)
		}
	}

	if err := challenges.Consume(challengeID, userID, "enroll", now); err != nil {
		return nil, err
	}

	transportsJSON := "[]"
	if len(in.Transports) > 0 {
		b, _ := json.Marshal(in.Transports)
		transportsJSON = string(b)
	}
	aaguid := in.AAGUID
	if aaguid == nil {
		aaguid = []byte{}
	}
	if cose == nil {
		cose = []byte{}
	}
	cred := &Credential{
		ID:                hex.EncodeToString(in.CredentialID),
		UserID:            userID,
		CredentialID:      append([]byte(nil), in.CredentialID...),
		PublicKey:         ed25519.PublicKey(append([]byte(nil), pub...)),
		PublicKeyCOSE:     cose,
		PublicKeyAlg:      alg,
		AAGUID:            append([]byte(nil), aaguid...),
		Transports:        append([]string(nil), in.Transports...),
		AttestationFormat: in.AttestationFormat,
		Nickname:          in.Nickname,
		CreatedAt:         now,
	}
	_, err := cs.db.ExecContext(ctx, `INSERT INTO webauthn_credentials(
		id, user_id, credential_id, public_key, sign_count, created_at,
		public_key_cose, public_key_alg, aaguid, transports_json, attestation_format, nickname)
		VALUES(?,?,?,?,0,?,?,?,?,?,?,?)`,
		cred.ID, userID, cred.CredentialID, []byte(cred.PublicKey), now.Format(time.RFC3339Nano),
		cred.PublicKeyCOSE, cred.PublicKeyAlg, aaguid, transportsJSON, cred.AttestationFormat, cred.Nickname)
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
		id, userID, created, transportsJSON, fmtName, nick string
		pub, cose, aaguid                                  []byte
		signCount                                          int
		alg                                                int64
		storedCredID                                       []byte
	)
	err := cs.db.QueryRowContext(ctx, `SELECT id, user_id, credential_id, public_key, sign_count, created_at,
		public_key_cose, public_key_alg, aaguid, transports_json, attestation_format, nickname
		FROM webauthn_credentials WHERE credential_id=?`, credentialID).
		Scan(&id, &userID, &storedCredID, &pub, &signCount, &created,
			&cose, &alg, &aaguid, &transportsJSON, &fmtName, &nick)
	if err == sql.ErrNoRows {
		return nil, ErrWebAuthnUnknown
	}
	if err != nil {
		return nil, err
	}
	var transports []string
	_ = json.Unmarshal([]byte(transportsJSON), &transports)
	cred := &Credential{
		ID: id, UserID: userID, CredentialID: storedCredID,
		PublicKey: ed25519.PublicKey(pub), PublicKeyCOSE: cose, PublicKeyAlg: alg,
		AAGUID: aaguid, Transports: transports, AttestationFormat: fmtName, Nickname: nick,
		SignCount: uint32(signCount),
	}
	cred.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return cred, nil
}

// AssertLogin verifies a signed challenge and consumes it (login or step_up).
// Prefers webauthncose.VerifySignature when a COSE public key is stored.
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
	if err := verifyAssertion(cred, []byte(challengeID), signature); err != nil {
		return nil, err
	}
	if err := challenges.Consume(challengeID, userID, purpose, now); err != nil {
		return nil, err
	}
	_, _ = cs.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=sign_count+1 WHERE id=?`, cred.ID)
	cred.SignCount++
	return cred, nil
}

func verifyAssertion(cred *Credential, data, signature []byte) error {
	if len(cred.PublicKeyCOSE) > 0 {
		key, err := webauthncose.ParsePublicKey(cred.PublicKeyCOSE)
		if err == nil {
			ok, err := webauthncose.VerifySignature(key, data, signature)
			if err == nil && ok {
				return nil
			}
			// Fall through to raw Ed25519 for legacy enrollments / dual-path tests.
		}
	}
	if len(cred.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(cred.PublicKey, data, signature) {
		return nil
	}
	return ErrWebAuthnInvalid
}

// MarshalEd25519COSE encodes an Ed25519 public key as a COSE OKP key (alg EdDSA).
func MarshalEd25519COSE(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, ErrWebAuthnInvalid
	}
	key := webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgEdDSA),
		},
		Curve:  int64(webauthncose.Ed25519),
		XCoord: append([]byte(nil), pub...),
	}
	return webauthncbor.Marshal(key)
}

func okpRawEd25519(key any) []byte {
	switch k := key.(type) {
	case webauthncose.OKPPublicKeyData:
		if len(k.XCoord) == ed25519.PublicKeySize {
			return k.XCoord
		}
	case *webauthncose.OKPPublicKeyData:
		if k != nil && len(k.XCoord) == ed25519.PublicKeySize {
			return k.XCoord
		}
	}
	return nil
}

func coseAlg(key any) int64 {
	switch k := key.(type) {
	case webauthncose.OKPPublicKeyData:
		return k.Algorithm
	case *webauthncose.OKPPublicKeyData:
		if k != nil {
			return k.Algorithm
		}
	case webauthncose.EC2PublicKeyData:
		return k.Algorithm
	case *webauthncose.EC2PublicKeyData:
		if k != nil {
			return k.Algorithm
		}
	}
	return 0
}

// GenerateDeviceKeypair creates an Ed25519 keypair for tests / local enroll helpers.
func GenerateDeviceKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
