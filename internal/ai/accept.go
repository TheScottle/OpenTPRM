package ai

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrSuggestionNotProposed = errors.New("suggestion not in proposed status")
	ErrMissingSourceText     = errors.New("source text required to verify citations")
)

// AcceptRequest carries human accept of a suggestion with citation verification (AI-064).
type AcceptRequest struct {
	SuggestionID string
	SourceText   string
	Actor        string
}

// AcceptResult is returned after citations verify and status moves to accepted.
type AcceptResult struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Citations []Citation      `json:"citations"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Label     string          `json:"label"`
}

// VerifyCitationsAgainstSource checks every citation quote exists in source text.
func VerifyCitationsAgainstSource(sourceText string, citations []Citation) error {
	if len(citations) == 0 {
		return nil
	}
	if sourceText == "" {
		return ErrMissingSourceText
	}
	for i, c := range citations {
		if err := VerifyCitation(sourceText, c.Quote); err != nil {
			return fmt.Errorf("citation[%d] source_id=%s: %w", i, c.SourceID, err)
		}
	}
	return nil
}

// PrepareAccept validates citations for accept; caller persists status=accepted.
func PrepareAccept(status string, citations []Citation, sourceText string) error {
	if status != "" && status != "proposed" {
		return ErrSuggestionNotProposed
	}
	return VerifyCitationsAgainstSource(sourceText, citations)
}
