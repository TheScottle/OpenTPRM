package offboarding

import "testing"

func TestOFF_001_DefaultChecklist(t *testing.T) {
	items := DefaultItems()
	if len(items) < 8 {
		t.Fatalf("expected OFF-001 items, got %d", len(items))
	}
	raw, err := ItemsJSON(nil)
	if err != nil || raw == "" {
		t.Fatal(err)
	}
	parsed, err := ParseItems(raw)
	if err != nil || len(parsed) != len(items) {
		t.Fatal(err)
	}
	updated, ok := MarkDone(parsed, "revoke_accounts", true, "ev-1")
	if !ok || !updated[0].Done || updated[0].EvidenceRef != "ev-1" {
		t.Fatal("mark done failed")
	}
	if AllDone(updated) {
		t.Fatal("not all done yet")
	}
	for i := range updated {
		updated[i].Done = true
	}
	if !AllDone(updated) {
		t.Fatal("expected all done")
	}
}
