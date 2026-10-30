package assessment

import (
	"testing"
	"testing/quick"
)

func TestASM_001_LegalTransitions(t *testing.T) {
	if err := CanTransition(Draft, Scoping); err != nil {
		t.Fatal(err)
	}
	if err := CanTransition(PendingApproval, Approved); err != nil {
		t.Fatal(err)
	}
}

func TestASM_001_IllegalTransitions(t *testing.T) {
	if err := CanTransition(Draft, Approved); err == nil {
		t.Fatal("draft → approved must fail")
	}
	if err := CanTransition(Closed, Draft); err == nil {
		t.Fatal("closed → draft must fail")
	}
}

func TestASM_001_PropertyNoIllegal(t *testing.T) {
	states := AllStates()
	fn := func(fi, ti byte) bool {
		from := states[int(fi)%len(states)]
		to := states[int(ti)%len(states)]
		err := CanTransition(from, to)
		allowed := false
		for _, s := range transitions[from] {
			if s == to {
				allowed = true
				break
			}
		}
		if allowed && err != nil {
			return false
		}
		if !allowed && err == nil {
			return false
		}
		return true
	}
	if err := quick.Check(fn, &quick.Config{MaxCount: 200}); err != nil {
		t.Fatal(err)
	}
}
