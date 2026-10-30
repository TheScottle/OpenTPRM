package intake

import "testing"

func TestAT_01_PrivilegedAndClientConfidential(t *testing.T) {
	f := Factors{
		DataSensitivity:        5,
		ClientConfidential:     true,
		PrivilegedAccess:       4,
		OperationalCriticality: 3,
		RegulatoryExposure:     3,
		SystemAccess:           3,
		DataVolume:             3,
		ExternalImpact:         2,
		VendorAIUse:            2,
		FourthPartyReliance:    2,
		FinancialDependency:    2,
		Jurisdiction:           2,
		Substitutability:       3,
	}
	r := ComputeTier(f)
	if r.Tier > 2 {
		t.Fatalf("AT-01: expected tier <= 2, got %d (score=%v floors=%v)", r.Tier, r.Score, r.FloorsApplied)
	}
	if !rHas(r, "independent") && r.Tier <= 2 {
		plan := DiligencePlan(r.Tier, f)
		if plan["assurance"] != true {
			t.Fatalf("AT-01: plan must request independent assurance for tier %d", r.Tier)
		}
	}
}

func rHas(r Result, _ string) bool { return false }

func TestScoreBands(t *testing.T) {
	low := ComputeTier(Factors{
		DataSensitivity: 1, OperationalCriticality: 1, PrivilegedAccess: 1,
		RegulatoryExposure: 1, SystemAccess: 1, DataVolume: 1, ExternalImpact: 1,
		VendorAIUse: 1, FourthPartyReliance: 1, FinancialDependency: 1, Jurisdiction: 1,
		Substitutability: 5,
	})
	if low.Tier != 4 {
		t.Fatalf("expected tier 4, got %d score %v", low.Tier, low.Score)
	}
}
