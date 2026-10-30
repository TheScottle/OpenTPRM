// Package contract helpers for clause checklists and client requirement flow-down (CON-*).
package contract

import (
	"encoding/json"
	"fmt"
)

// ClauseStatus values for CON-002 checklists.
const (
	ClausePresent = "present"
	ClausePartial = "partial"
	ClauseAbsent  = "absent"
)

// ClauseItem is one tier-driven checklist row.
type ClauseItem struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Status    string `json:"status"` // present|partial|absent
	Reference string `json:"reference,omitempty"`
}

// DefaultTier1Clauses returns a configurable starter checklist (CON-002).
func DefaultTier1Clauses() []ClauseItem {
	labels := []string{
		"security_exhibit", "right_to_audit", "breach_notice_window", "data_location",
		"subprocessor_notice", "encryption", "return_destruction", "termination_assistance",
		"bcp", "insurance", "breach_indemnity", "confidentiality_privilege",
		"no_training_on_firm_data", "personnel_screening", "client_ocg_compliance",
	}
	out := make([]ClauseItem, len(labels))
	for i, id := range labels {
		out[i] = ClauseItem{ID: id, Label: id, Status: ClauseAbsent}
	}
	return out
}

// ClausesJSON marshals clause items.
func ClausesJSON(items []ClauseItem) (string, error) {
	b, err := json.Marshal(items)
	return string(b), err
}

// FlowDown describes CON-004: client requirement → engagement obligation.
type FlowDown struct {
	ClientID      string
	RequirementID string
	EngagementID  string
	Description   string
	Source        string
}

// Validate ensures required flow-down fields are present.
func (f FlowDown) Validate() error {
	if f.ClientID == "" || f.RequirementID == "" || f.EngagementID == "" || f.Description == "" {
		return fmt.Errorf("client_id, requirement_id, engagement_id, and description required")
	}
	if f.Source == "" {
		return fmt.Errorf("source required")
	}
	return nil
}
