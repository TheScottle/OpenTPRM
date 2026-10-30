package questionnaire_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
)

func TestAT_15_DeltaPrefill(t *testing.T) {
	prior := map[string]any{"IAM-03": "yes", "GOV-01": "yes"}
	current := map[string]any{"IAM-03": "partial", "GOV-01": "yes"}
	d := questionnaire.BuildDeltaPrefill(prior, current)
	if len(d.ChangedKeys) != 1 || d.ChangedKeys[0] != "IAM-03" {
		t.Fatalf("changed=%v", d.ChangedKeys)
	}
	found := false
	for _, k := range d.RequiresConfirm {
		if k == "GOV-01" {
			found = true
		}
	}
	if !found {
		t.Fatal("unchanged answers must require confirmation")
	}
}
