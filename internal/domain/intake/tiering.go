package intake

import "math"

// Factors are scored 1–5 per App. A.
type Factors struct {
	DataSensitivity       int `json:"data_sensitivity"`
	OperationalCriticality int `json:"operational_criticality"`
	PrivilegedAccess      int `json:"privileged_access"`
	RegulatoryExposure    int `json:"regulatory_exposure"`
	SystemAccess          int `json:"system_access"`
	DataVolume            int `json:"data_volume"`
	ExternalImpact        int `json:"external_impact"`
	VendorAIUse           int `json:"vendor_ai_use"`
	FourthPartyReliance   int `json:"fourth_party_reliance"`
	FinancialDependency   int `json:"financial_dependency"`
	Jurisdiction          int `json:"jurisdiction"`
	// Metadata for floors
	Substitutability int  `json:"substitutability"` // 1=low .. 5=high
	PHIUnderBAA      bool `json:"phi_under_baa"`
	ClientConfidential bool `json:"client_confidential"`
}

// Result of tier computation.
type Result struct {
	Score         float64  `json:"score"`
	Tier          int      `json:"tier"`
	FloorsApplied []string `json:"floors_applied"`
	Breakdown     map[string]float64 `json:"breakdown"`
}

var weights = map[string]float64{
	"data_sensitivity":        0.18,
	"operational_criticality": 0.14,
	"privileged_access":       0.12,
	"regulatory_exposure":     0.12,
	"system_access":           0.10,
	"data_volume":             0.08,
	"external_impact":         0.06,
	"vendor_ai_use":           0.06,
	"fourth_party_reliance":   0.05,
	"financial_dependency":    0.05,
	"jurisdiction":            0.04,
}

// ComputeTier computes inherent risk tier (App. A). AI never computes this.
func ComputeTier(f Factors) Result {
	clamp := func(v int) int {
		if v < 1 {
			return 1
		}
		if v > 5 {
			return 5
		}
		return v
	}
	vals := map[string]int{
		"data_sensitivity":        clamp(f.DataSensitivity),
		"operational_criticality": clamp(f.OperationalCriticality),
		"privileged_access":       clamp(f.PrivilegedAccess),
		"regulatory_exposure":     clamp(f.RegulatoryExposure),
		"system_access":           clamp(f.SystemAccess),
		"data_volume":             clamp(f.DataVolume),
		"external_impact":         clamp(f.ExternalImpact),
		"vendor_ai_use":           clamp(f.VendorAIUse),
		"fourth_party_reliance":   clamp(f.FourthPartyReliance),
		"financial_dependency":    clamp(f.FinancialDependency),
		"jurisdiction":            clamp(f.Jurisdiction),
	}
	breakdown := map[string]float64{}
	var score float64
	for k, w := range weights {
		contrib := w * float64(vals[k])
		breakdown[k] = contrib
		score += contrib
	}
	tier := scoreToTier(score)
	var floors []string
	// Floors: more severe (lower number) wins
	apply := func(maxTier int, reason string) {
		if tier > maxTier {
			tier = maxTier
			floors = append(floors, reason)
		}
	}
	if vals["privileged_access"] >= 4 {
		apply(2, "privileged_access>=4")
	}
	if vals["data_sensitivity"] == 5 && vals["data_volume"] >= 3 {
		apply(2, "sensitivity5_volume>=3")
	}
	if vals["operational_criticality"] == 5 && f.Substitutability > 0 && f.Substitutability <= 2 {
		apply(1, "criticality5_low_substitutability")
	}
	if f.PHIUnderBAA {
		apply(2, "phi_under_baa")
	}
	if f.ClientConfidential && vals["data_sensitivity"] < 4 {
		vals["data_sensitivity"] = 4
	}
	if f.ClientConfidential {
		apply(2, "client_confidential")
	}
	return Result{Score: math.Round(score*100) / 100, Tier: tier, FloorsApplied: floors, Breakdown: breakdown}
}

func scoreToTier(score float64) int {
	switch {
	case score >= 4.0:
		return 1
	case score >= 3.0:
		return 2
	case score >= 2.0:
		return 3
	default:
		return 4
	}
}

// FactorsFromAnswers maps intake answers to factors (deterministic).
func FactorsFromAnswers(answers map[string]any) Factors {
	f := Factors{
		DataSensitivity:        1,
		OperationalCriticality: 1,
		PrivilegedAccess:       1,
		RegulatoryExposure:     1,
		SystemAccess:           1,
		DataVolume:             1,
		ExternalImpact:         1,
		VendorAIUse:            1,
		FourthPartyReliance:    1,
		FinancialDependency:    1,
		Jurisdiction:           1,
		Substitutability:       3,
	}
	asInt := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := answers[k]; ok {
				switch t := v.(type) {
				case float64:
					return int(t)
				case int:
					return t
				case string:
					switch t {
					case "yes", "privileged", "client_confidential", "confidential":
						return 5
					case "high":
						return 4
					case "medium":
						return 3
					case "low":
						return 2
					}
				}
			}
		}
		return 0
	}
	if v := asInt("privileged_access", "access_privileged"); v > 0 {
		f.PrivilegedAccess = v
	}
	if v := asInt("data_sensitivity", "classification"); v > 0 {
		f.DataSensitivity = v
	}
	if v, ok := answers["client_confidential"].(bool); ok && v {
		f.ClientConfidential = true
		f.DataSensitivity = 5
	}
	if s, ok := answers["highest_classification"].(string); ok {
		switch s {
		case "Client-Confidential", "Privileged":
			f.ClientConfidential = true
			f.DataSensitivity = 5
		case "Confidential":
			f.DataSensitivity = 4
		}
	}
	if v, ok := answers["phi_under_baa"].(bool); ok {
		f.PHIUnderBAA = v
	}
	if v := asInt("data_volume"); v > 0 {
		f.DataVolume = v
	}
	if v := asInt("operational_criticality", "criticality"); v > 0 {
		f.OperationalCriticality = v
	}
	if v := asInt("system_access"); v > 0 {
		f.SystemAccess = v
	}
	return f
}

// DiligencePlan returns default plan modules by tier.
func DiligencePlan(tier int, f Factors) map[string]any {
	plan := map[string]any{
		"tier":            tier,
		"questionnaire":   "OpenTPRM Lite",
		"assurance":       false,
		"review_domains":  []string{"security"},
		"reassess_months": 36,
	}
	switch tier {
	case 1:
		plan["questionnaire"] = "OpenTPRM Core"
		plan["overlays"] = []string{"applicable"}
		plan["assurance"] = true
		plan["assurance_types"] = []string{"SOC2_T2_or_ISO27001", "pen_test_summary", "bcp_dr", "insurance"}
		plan["review_domains"] = []string{"security", "privacy", "legal", "bcp", "ai"}
		plan["reassess_months"] = 12
		plan["approver_required"] = true
	case 2:
		plan["questionnaire"] = "OpenTPRM Core"
		plan["assurance"] = true
		plan["assurance_types"] = []string{"independent_assurance"}
		plan["review_domains"] = []string{"security", "legal"}
		plan["reassess_months"] = 12
	case 3:
		plan["questionnaire"] = "OpenTPRM Lite"
		plan["assurance"] = false
		plan["reassess_months"] = 24
	}
	_ = f
	return plan
}
