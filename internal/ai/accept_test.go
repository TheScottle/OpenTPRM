package ai_test

import (
	"errors"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/ai"
)

func TestAI_AcceptRequiresVerifiedCitations(t *testing.T) {
	cites := []ai.Citation{{SourceID: "ev1", Quote: "encrypts data at rest", Page: 3}}
	src := "The vendor encrypts data at rest using AES-256."
	if err := ai.PrepareAccept("proposed", cites, src); err != nil {
		t.Fatal(err)
	}
	if err := ai.PrepareAccept("proposed", cites, "unrelated text"); !errors.Is(err, ai.ErrUnverifiedCitation) {
		t.Fatalf("want unverified, got %v", err)
	}
	if err := ai.PrepareAccept("accepted", cites, src); err != ai.ErrSuggestionNotProposed {
		t.Fatalf("got %v", err)
	}
	if err := ai.PrepareAccept("proposed", cites, ""); err != ai.ErrMissingSourceText {
		t.Fatalf("got %v", err)
	}
}
