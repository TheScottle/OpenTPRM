package ai_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/ai"
)

type memWriter struct {
	last ai.Suggestion
}

func (m *memWriter) CreateSuggestion(ctx context.Context, kind string, payload json.RawMessage, citations []ai.Citation, classification string) (ai.Suggestion, error) {
	m.last = ai.Suggestion{ID: "s1", Kind: kind, Payload: payload, Citations: citations, Status: "proposed"}
	return m.last, nil
}

func TestAI_JobStubCreatesSuggestionsOnly(t *testing.T) {
	w := &memWriter{}
	res, err := ai.RunSuggestJob(context.Background(), true, w, ai.JobRequest{
		Type: "suggest", Kind: "finding_draft", Payload: json.RawMessage(`{"title":"x"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Suggestion.Kind != "finding_draft" || res.State != "completed" {
		t.Fatalf("%+v", res)
	}
	if _, err := ai.RunSuggestJob(context.Background(), true, w, ai.JobRequest{Type: "approve"}); err != ai.ErrJobNotSuggestOnly {
		t.Fatalf("got %v", err)
	}
	if _, err := ai.RunSuggestJob(context.Background(), false, w, ai.JobRequest{Type: "suggest"}); err != ai.ErrAssistDisabled {
		t.Fatalf("got %v", err)
	}
}
