// Package exception implements signed risk-acceptance decision records (EXC-*, ASM-006).
package exception

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Formula / schema version for the canonical decision payload.
const PayloadVersion = "decision/v1"

var (
	ErrInvalidKey     = errors.New("invalid ed25519 key")
	ErrBadSignature   = errors.New("decision signature verification failed")
	ErrCanonicalEmpty = errors.New("canonical payload empty")
)

// Payload is the canonical decision record (ASM-006 / EXC-002).
// Field order and json tags define the signed byte sequence after CanonicalJSON.
type Payload struct {
	Version        string    `json:"version"`
	AssessmentID   string    `json:"assessment_id"`
	ExceptionID    string    `json:"exception_id,omitempty"`
	ResidualRating string    `json:"residual_rating"`
	Conditions     []string  `json:"conditions"`
	ApproverID     string    `json:"approver_id"`
	DecidedAt      time.Time `json:"decided_at"`
	EvidenceHashes []string  `json:"evidence_hashes"`
	Scope          string    `json:"scope,omitempty"`
	Expiry         time.Time `json:"expiry,omitempty"`
	RationaleHash  string    `json:"rationale_hash,omitempty"`
}

// Decision is a signed payload.
type Decision struct {
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"` // hex-encoded Ed25519 signature
	KeyID     string  `json:"key_id,omitempty"`
}

// CanonicalJSON returns deterministic JSON bytes for signing.
// Conditions and evidence hashes are copied and sorted for stability.
func (p Payload) CanonicalJSON() ([]byte, error) {
	cp := p
	cp.Version = PayloadVersion
	cp.Conditions = append([]string(nil), p.Conditions...)
	cp.EvidenceHashes = append([]string(nil), p.EvidenceHashes...)
	sortStrings(cp.Conditions)
	sortStrings(cp.EvidenceHashes)
	// Use fixed RFC3339Nano UTC for timestamps via a DTO to avoid monotonic clock noise.
	dto := struct {
		Version        string   `json:"version"`
		AssessmentID   string   `json:"assessment_id"`
		ExceptionID    string   `json:"exception_id,omitempty"`
		ResidualRating string   `json:"residual_rating"`
		Conditions     []string `json:"conditions"`
		ApproverID     string   `json:"approver_id"`
		DecidedAt      string   `json:"decided_at"`
		EvidenceHashes []string `json:"evidence_hashes"`
		Scope          string   `json:"scope,omitempty"`
		Expiry         string   `json:"expiry,omitempty"`
		RationaleHash  string   `json:"rationale_hash,omitempty"`
	}{
		Version:        PayloadVersion,
		AssessmentID:   cp.AssessmentID,
		ExceptionID:    cp.ExceptionID,
		ResidualRating: cp.ResidualRating,
		Conditions:     cp.Conditions,
		ApproverID:     cp.ApproverID,
		DecidedAt:      cp.DecidedAt.UTC().Format(time.RFC3339Nano),
		EvidenceHashes: cp.EvidenceHashes,
		Scope:          cp.Scope,
		RationaleHash:  cp.RationaleHash,
	}
	if !cp.Expiry.IsZero() {
		dto.Expiry = cp.Expiry.UTC().Format(time.RFC3339Nano)
	}
	return json.Marshal(dto)
}

// Hash returns SHA-256 hex of the canonical payload (for audit linkage).
func (p Payload) Hash() (string, error) {
	b, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Sign produces an Ed25519 signature over the canonical payload.
func Sign(priv ed25519.PrivateKey, p Payload) (Decision, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Decision{}, ErrInvalidKey
	}
	body, err := p.CanonicalJSON()
	if err != nil {
		return Decision{}, err
	}
	if len(body) == 0 {
		return Decision{}, ErrCanonicalEmpty
	}
	sig := ed25519.Sign(priv, body)
	return Decision{
		Payload:   p,
		Signature: hex.EncodeToString(sig),
	}, nil
}

// Verify checks the Ed25519 signature over the canonical payload.
func Verify(pub ed25519.PublicKey, d Decision) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	body, err := d.Payload.CanonicalJSON()
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return ErrBadSignature
	}
	return nil
}

// GenerateKey returns a new Ed25519 key pair for tests and bootstrap.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

func sortStrings(ss []string) { sort.Strings(ss) }
