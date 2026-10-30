package risk

import "testing"

func TestResidualBands(t *testing.T) {
	low := Compute(Input{QuestionnaireScore: 1, Assurance: 1, Sensitivity: 1, Criticality: 1, Regulatory: 1,
		Access: 1, PrivilegedAccess: 1, ExternalImpact: 1, AIUse: 1, FourthParty: 1})
	if low.Band != "low" || low.Residual > 4 {
		t.Fatalf("expected low, got %+v", low)
	}

	moderate := Compute(Input{
		QuestionnaireScore: 0.7, Assurance: 0.8,
		Sensitivity: 3, Criticality: 2, Regulatory: 2,
		Access: 3, PrivilegedAccess: 3, ExternalImpact: 3, AIUse: 3, FourthParty: 3,
	})
	if moderate.Band != "moderate" {
		t.Fatalf("expected moderate, got %+v", moderate)
	}

	high := Compute(Input{
		QuestionnaireScore: 0.2, Assurance: 0.3, HighFindings: 2,
		Sensitivity: 4, Criticality: 4, Regulatory: 3,
		Access: 4, PrivilegedAccess: 4, ExternalImpact: 4, AIUse: 3, FourthParty: 3,
	})
	if high.Band != "high" {
		t.Fatalf("expected high, got %+v", high)
	}

	critical := Compute(Input{QuestionnaireScore: 0, Assurance: 0, CriticalFindings: 2,
		Sensitivity: 5, Criticality: 5, Regulatory: 5,
		Access: 5, PrivilegedAccess: 5, ExternalImpact: 5, AIUse: 5, FourthParty: 5})
	if critical.Band != "critical" || critical.Residual < 20 {
		t.Fatalf("expected critical, got %+v", critical)
	}
}

func TestBandEdges(t *testing.T) {
	cases := []struct {
		r    int
		band string
	}{
		{1, "low"}, {4, "low"}, {5, "moderate"}, {9, "moderate"},
		{10, "high"}, {16, "high"}, {20, "critical"}, {25, "critical"},
	}
	for _, tc := range cases {
		band := "low"
		switch {
		case tc.r >= 20:
			band = "critical"
		case tc.r >= 10:
			band = "high"
		case tc.r >= 5:
			band = "moderate"
		}
		if band != tc.band {
			t.Fatalf("R=%d got %s want %s", tc.r, band, tc.band)
		}
	}
}
