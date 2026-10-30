// Package finding implements finding status transitions and remediation helpers (FND-*).
package finding

import "fmt"

// Status values (FND-002).
type Status string

const (
	Open              Status = "open"
	Acknowledged      Status = "acknowledged"
	PlanAgreed        Status = "plan_agreed"
	InProgress        Status = "in_progress"
	PendingValidation Status = "pending_validation"
	Closed            Status = "closed"
	RiskAccepted      Status = "risk_accepted"
	FalsePositive     Status = "false_positive"
)

var transitions = map[Status][]Status{
	Open:              {Acknowledged, RiskAccepted, FalsePositive},
	Acknowledged:      {PlanAgreed, RiskAccepted, FalsePositive},
	PlanAgreed:        {InProgress, RiskAccepted},
	InProgress:        {PendingValidation, RiskAccepted},
	PendingValidation: {Closed, InProgress},
	Closed:            {},
	RiskAccepted:      {},
	FalsePositive:     {},
}

// CanTransition returns nil if from→to is allowed (FND-002).
func CanTransition(from, to Status) error {
	allowed, ok := transitions[from]
	if !ok {
		return fmt.Errorf("unknown finding status %q", from)
	}
	for _, s := range allowed {
		if s == to {
			return nil
		}
	}
	return fmt.Errorf("illegal finding transition %s → %s", from, to)
}

// DefaultSLADays returns FND-003 defaults by severity.
func DefaultSLADays(severity string) int {
	switch severity {
	case "critical":
		return 30
	case "high":
		return 60
	case "medium":
		return 90
	case "low":
		return 180
	default:
		return 90
	}
}

// RequiresClosureEvidence is true for closed transitions (FND-005).
func RequiresClosureEvidence(to Status) bool {
	return to == Closed
}
