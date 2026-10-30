package contract

import "testing"

func TestCON_002_004_ClausesAndFlowDown(t *testing.T) {
	items := DefaultTier1Clauses()
	if len(items) < 10 {
		t.Fatal("tier1 clause checklist too short")
	}
	raw, err := ClausesJSON(items)
	if err != nil || raw == "" {
		t.Fatal(err)
	}
	fd := FlowDown{
		ClientID: "c1", RequirementID: "r1", EngagementID: "e1",
		Description: "No training on client data", Source: "client_ocg",
	}
	if err := fd.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (FlowDown{}).Validate(); err == nil {
		t.Fatal("empty flow-down must fail")
	}
}
