package changerequest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrStaleETag = errors.New("change request stale: target ETag mismatch")
	ErrPatchTamper = errors.New("change request patch hash mismatch")
)

// Request is a T3 change request pending human approval (AI-041/042).
type Request struct {
	ID           string          `json:"id"`
	Action       string          `json:"action"`
	TargetType   string          `json:"target_type"`
	TargetID     string          `json:"target_id"`
	Patch        json.RawMessage `json:"patch"`
	PatchSHA256  string          `json:"patch_sha256"`
	TargetETag   string          `json:"target_etag"`
	Rationale    string          `json:"rationale"`
	RenderedMsg  string          `json:"rendered_message,omitempty"`
	Recipients   []string        `json:"recipients,omitempty"`
	Status       string          `json:"status"`
}

// HashPatch returns SHA-256 of canonical patch bytes.
func HashPatch(patch json.RawMessage) string {
	sum := sha256.Sum256(patch)
	return hex.EncodeToString(sum[:])
}

// Approve validates freshness then marks approved (human only).
func Approve(cr Request, currentETag string, recomputedPatch json.RawMessage) (Request, error) {
	if HashPatch(recomputedPatch) != cr.PatchSHA256 {
		return cr, ErrPatchTamper
	}
	if currentETag != cr.TargetETag {
		return cr, ErrStaleETag
	}
	cr.Status = "approved"
	return cr, nil
}

// OutboundRequiresHumanGate documents AT-05: questionnaire_send etc. never send until approved.
func OutboundRequiresHumanGate(action string) bool {
	switch action {
	case "questionnaire_send", "evidence_request_send", "reminder_send":
		return true
	default:
		return false
	}
}

func ValidateAction(action string) error {
	switch action {
	case "assessment_create", "intake_create", "task_create", "task_assign", "due_date_set",
		"finding_create_from_suggestion", "questionnaire_send", "evidence_request_send", "reminder_send":
		return nil
	default:
		return fmt.Errorf("unknown change request action %q", action)
	}
}
