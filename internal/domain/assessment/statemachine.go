package assessment

import "fmt"

type State string

const (
	Draft                  State = "draft"
	Scoping                State = "scoping"
	InDiligence            State = "in_diligence"
	UnderReview            State = "under_review"
	Remediation            State = "remediation"
	PendingApproval        State = "pending_approval"
	Approved               State = "approved"
	ApprovedWithConditions State = "approved_with_conditions"
	Rejected               State = "rejected"
	Closed                 State = "closed"
	OnHold                 State = "on_hold"
	Cancelled              State = "cancelled"
)

var transitions = map[State][]State{
	Draft:           {Scoping, OnHold, Cancelled},
	Scoping:         {InDiligence, OnHold, Cancelled},
	InDiligence:     {UnderReview, OnHold, Cancelled},
	UnderReview:     {Remediation, PendingApproval, OnHold, Cancelled},
	Remediation:     {UnderReview, PendingApproval, OnHold, Cancelled},
	PendingApproval: {Approved, ApprovedWithConditions, Rejected, OnHold, Cancelled},
	Approved:        {Closed},
	ApprovedWithConditions: {Remediation, Closed},
	Rejected:        {Closed, Scoping},
	OnHold:          {Draft, Scoping, InDiligence, UnderReview, Remediation, PendingApproval, Cancelled},
	Cancelled:       {},
	Closed:          {},
}

// CanTransition returns nil if from→to is allowed (ASM-001).
func CanTransition(from, to State) error {
	allowed, ok := transitions[from]
	if !ok {
		return fmt.Errorf("unknown state %q", from)
	}
	for _, s := range allowed {
		if s == to {
			return nil
		}
	}
	return fmt.Errorf("illegal transition %s → %s", from, to)
}

// AllStates returns every defined state.
func AllStates() []State {
	return []State{Draft, Scoping, InDiligence, UnderReview, Remediation, PendingApproval,
		Approved, ApprovedWithConditions, Rejected, Closed, OnHold, Cancelled}
}
