package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// CallLogWriter persists AI call log rows (hashes only).
type CallLogWriter interface {
	WriteCallLog(ctx context.Context, endpointID, modelDigest, templateHash, inputHash, outputHash, principal string, tokens, latencyMs int) error
}

// JobRequest is a stub inference job that may only emit suggestions.
type JobRequest struct {
	Type           string          `json:"type"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	Citations      []Citation      `json:"citations,omitempty"`
	Classification string          `json:"classification,omitempty"`
	EngagementID   string          `json:"engagement_id,omitempty"`
	EndpointID     string          `json:"endpoint_id,omitempty"`
	ModelDigest    string          `json:"model_digest,omitempty"`
	TemplateHash   string          `json:"template_hash,omitempty"`
	Principal      string          `json:"principal,omitempty"`
}

// JobResult is the outcome of a suggestions-only AI job.
type JobResult struct {
	JobID      string     `json:"job_id"`
	State      string     `json:"state"`
	Suggestion Suggestion `json:"suggestion"`
	CallLogID  string     `json:"call_log_id,omitempty"`
}

// RunSuggestJob creates a suggestion record and refuses any non-suggest job type.
func RunSuggestJob(ctx context.Context, enabled bool, w SuggestionWriter, req JobRequest) (JobResult, error) {
	return RunSuggestJobWithLog(ctx, enabled, w, nil, req)
}

// RunSuggestJobWithLog is RunSuggestJob plus optional ai_call_logs write.
func RunSuggestJobWithLog(ctx context.Context, enabled bool, w SuggestionWriter, logs CallLogWriter, req JobRequest) (JobResult, error) {
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
	start := time.Now()
	sug, err := w.CreateSuggestion(ctx, kind, payload, req.Citations, class)
	if err != nil {
		return JobResult{}, err
	}
	if sug.ID == "" {
		sug.ID = uuid.Must(uuid.NewV7()).String()
	}
	sug.Status = "proposed"
	sug.Label = "AI suggestion — human review required"
	jobID := uuid.Must(uuid.NewV7()).String()
	res := JobResult{JobID: jobID, State: "completed", Suggestion: sug}
	if logs != nil {
		inHash := HashPrompt(string(payload), kind)
		outHash := HashPrompt(sug.ID, sug.Status, kind)
		ep := req.EndpointID
		if ep == "" {
			ep = "stub"
		}
		principal := req.Principal
		if principal == "" {
			principal = "system"
		}
		latency := int(time.Since(start).Milliseconds())
		if err := logs.WriteCallLog(ctx, ep, req.ModelDigest, req.TemplateHash, inHash, outHash, principal, 0, latency); err != nil {
			return JobResult{}, fmt.Errorf("ai call log: %w", err)
		}
		res.CallLogID = "written"
	}
	return res, nil
}
