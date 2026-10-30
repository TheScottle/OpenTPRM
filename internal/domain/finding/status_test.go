package finding

import "testing"

func TestFND_002_StatusTransitions(t *testing.T) {
	if err := CanTransition(Open, Acknowledged); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(Acknowledged, PlanAgreed); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(PlanAgreed, InProgress); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(InProgress, PendingValidation); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(PendingValidation, Closed); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(Open, Closed); err == nil {
		t.Fatal("open→closed must be rejected")
	}
	if err := CanTransition(Open, RiskAccepted); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(Open, FalsePositive); err != nil {
		t.Fatal(err)
	}
}

func TestFND_003_DefaultSLA(t *testing.T) {
	if DefaultSLADays("critical") != 30 || DefaultSLADays("high") != 60 {
		t.Fatal("SLA defaults")
	}
	if !RequiresClosureEvidence(Closed) || RequiresClosureEvidence(Open) {
		t.Fatal("closure evidence flag")
	}
}
