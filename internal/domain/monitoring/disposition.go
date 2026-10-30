// Package monitoring validates signal dispositions (MON-005).
package monitoring

import "fmt"

// Disposition is an analyst decision on a monitoring signal.
type Disposition string

const (
	New                 Disposition = "new"
	Dismissed           Disposition = "dismissed"
	Finding             Disposition = "finding"
	TriggeredAssessment Disposition = "triggered_assessment"
)

// Valid reports whether d is an allowed disposition value.
func Valid(d Disposition) bool {
	switch d {
	case New, Dismissed, Finding, TriggeredAssessment:
		return true
	default:
		return false
	}
}

// CanSet returns nil when an analyst may set to from from.
// Signals never auto-change ratings; only analyst dispositions are recorded (MON-005).
func CanSet(from, to Disposition) error {
	if !Valid(to) {
		return fmt.Errorf("unknown disposition %q", to)
	}
	if to == New {
		return fmt.Errorf("cannot reset disposition to new")
	}
	if from != New && from != "" && from == to {
		return nil
	}
	if from != New && from != "" {
		// Allow re-disposition for correction.
		return nil
	}
	return nil
}
