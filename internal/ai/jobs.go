package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrJobNotSuggestOnly = errors.New("AI jobs may only create suggestions")
	ErrAssistDisabled    = errors.New("ai_assist disabled")
)

// SuggestionWriter persists AI suggestions (never findings/approvals).
type SuggestionWriter interface {
	CreateSuggestion(ctx context.Context, kind string, payload json.RawMessage, citations []Citation, classification string) (Suggestion, error)
}

// JobRequest is a stub inference job that may only emit suggestions.
type JobRequest struct {
	Type           string          `json:"type"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	Citations      []Citation      `json:"citations,omitempty"`
	Classification string          `json:"classification,omitempty"`
	EngagementID   string          `json:"engagement_id,omitempty"`
}

// JobResult is the outcome of a suggestions-only AI job.
type JobResult struct {
	JobID      string     `json:"job_id"`
	State      string     `json:"state"`
	Suggestion Suggestion `json:"suggestion"`
}

// RunSuggestJob creates a suggestion record and refuses any non-suggest job type.
func RunSuggestJob(ctx context.Context, enabled bool, w SuggestionWriter, req JobRequest) (JobResult, error) {
	if !enabled {
		return JobResult{}, ErrAssistDisabled
	}
	if w == nil {
		return JobResult{}, fmt.Errorf("suggestion writer required")
	}
	typ := req.Type
	if typ == "" {
		typ = "suggest"
	}
	if typ != "suggest" && typ != "suggestion" {
		return JobResult{}, ErrJobNotSuggestOnly
	}
	kind := req.Kind
	if kind == "" {
		kind = "generic"
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	class := req.Classification
	if class == "" {
		class = "Internal"
	}
	sug, err := w.CreateSuggestion(ctx, kind, payload, req.Citations, class)
	if err != nil {
		return JobResult{}, err
	}
	if sug.ID == "" {
		sug.ID = uuid.Must(uuid.NewV7()).String()
	}
	sug.Status = "proposed"
	sug.Label = "AI suggestion — human review required"
	return JobResult{JobID: uuid.Must(uuid.NewV7()).String(), State: "completed", Suggestion: sug}, nil
}
