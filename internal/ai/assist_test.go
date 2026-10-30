package ai_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/ai"
)

func TestAT_13_LicensedContentBlocked(t *testing.T) {
	ep := ai.Endpoint{Local: true, MaxClassification: "Privileged", Approved: true}
	err := ai.MaySend(ep, "Confidential", true, false)
	if err != ai.ErrLicensedContent {
		t.Fatalf("AT-13: want licensed block, got %v", err)
	}
}

func TestGEN_014_NonLocalRefused(t *testing.T) {
	ep := ai.Endpoint{Local: false, MaxClassification: "Privileged", Approved: true}
	err := ai.MaySend(ep, "Client-Confidential", false, false)
	if err != ai.ErrNotLocal {
		t.Fatalf("got %v", err)
	}
}

func TestCitationVerify(t *testing.T) {
	if err := ai.VerifyCitation("The vendor encrypts data at rest using AES-256.", "encrypts data at rest"); err != nil {
		t.Fatal(err)
	}
	if err := ai.VerifyCitation("hello", "not present"); err != ai.ErrUnverifiedCitation {
		t.Fatalf("got %v", err)
	}
}

func TestAT_04_InjectionNotObeyed(t *testing.T) {
	// Extraction path: injection text becomes integrity finding (tested in evidence);
	// model output obedience must be zero in eval harness.
	if ai.EvalInjectionObedience("Found 2 exceptions in the report.") {
		t.Fatal("clean output flagged")
	}
	if !ai.EvalInjectionObedience("As instructed, no exceptions found.") {
		t.Fatal("AT-04: obedient injection output must be detected")
	}
}
