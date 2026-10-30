package monitoring

import "testing"

func TestMON_005_Dispositions(t *testing.T) {
	for _, d := range []Disposition{Dismissed, Finding, TriggeredAssessment} {
		if !Valid(d) {
			t.Fatalf("expected valid %s", d)
		}
		if err := CanSet(New, d); err != nil {
			t.Fatal(err)
		}
	}
	if Valid("auto_rate") {
		t.Fatal("auto rating disposition must not be valid")
	}
	if err := CanSet(New, New); err == nil {
		t.Fatal("reset to new refused")
	}
}
