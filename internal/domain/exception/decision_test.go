package exception

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		AssessmentID:   "asm-1",
		ExceptionID:    "exc-1",
		ResidualRating: "high",
		Conditions:     []string{"comp-control-b", "comp-control-a"},
		ApproverID:     "user-ciso",
		DecidedAt:      time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		EvidenceHashes: []string{"bbb", "aaa"},
		Scope:          "engagement:eng-1",
		Expiry:         time.Date(2027, 10, 30, 12, 0, 0, 0, time.UTC),
	}
	d, err := Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Signature == "" {
		t.Fatal("empty signature")
	}
	if err := Verify(pub, d); err != nil {
		t.Fatal(err)
	}
	// Canonicalization sorts conditions/hashes — verify still holds.
	d.Payload.Conditions = []string{"comp-control-a", "comp-control-b"}
	if err := Verify(pub, d); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Sign(priv, Payload{
		AssessmentID:   "asm-1",
		ResidualRating: "moderate",
		ApproverID:     "u1",
		DecidedAt:      time.Now().UTC(),
		Conditions:     []string{},
		EvidenceHashes: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.Payload.ResidualRating = "low"
	if err := Verify(pub, d); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Sign(priv, Payload{
		AssessmentID:   "asm-1",
		ResidualRating: "low",
		ApproverID:     "u1",
		DecidedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub2, d); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestInvalidKey(t *testing.T) {
	if _, err := Sign(ed25519.PrivateKey(nil), Payload{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("got %v", err)
	}
}

func TestCanonicalStable(t *testing.T) {
	p := Payload{
		AssessmentID:   "a",
		ResidualRating: "high",
		ApproverID:     "u",
		DecidedAt:      time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC),
		Conditions:     []string{"z", "a"},
		EvidenceHashes: []string{"2", "1"},
	}
	b1, err := p.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	p.Conditions = []string{"a", "z"}
	b2, err := p.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("canonical not stable:\n%s\n%s", b1, b2)
	}
}
