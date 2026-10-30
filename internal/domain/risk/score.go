package risk

import "math"

// Input for residual risk (App. A).
type Input struct {
	QuestionnaireScore float64 `json:"questionnaire_score"` // 0-1
	Assurance          float64 `json:"assurance"`           // 0-1
	CriticalFindings   int     `json:"critical_findings"`
	HighFindings       int     `json:"high_findings"`
	MediumFindings     int     `json:"medium_findings"`
	Sensitivity        int     `json:"sensitivity"`
	Criticality        int     `json:"criticality"`
	Regulatory         int     `json:"regulatory"`
	Access             int     `json:"access"`
	PrivilegedAccess   int     `json:"privileged_access"`
	ExternalImpact     int     `json:"external_impact"`
	AIUse              int     `json:"ai_use"`
	FourthParty        int     `json:"fourth_party"`
}

// Result of residual computation.
type Result struct {
	CE            float64 `json:"ce"`
	Magnitude     int     `json:"magnitude"`
	Likelihood    int     `json:"likelihood"`
	Residual      int     `json:"residual"`
	Band          string  `json:"band"`
	Explanation   string  `json:"explanation"`
	FormulaVersion string `json:"formula_version"`
}

// Compute residual risk R = M × L.
func Compute(in Input) Result {
	penalty := 0.25*float64(in.CriticalFindings) + 0.10*float64(in.HighFindings) + 0.03*float64(in.MediumFindings)
	if penalty > 0.6 {
		penalty = 0.6
	}
	ce := 0.55*in.QuestionnaireScore + 0.45*in.Assurance - penalty
	if ce < 0 {
		ce = 0
	}
	if ce > 1 {
		ce = 1
	}
	m := max3(in.Sensitivity, in.Criticality, in.Regulatory)
	e := math.Round((float64(in.Access+in.PrivilegedAccess+in.ExternalImpact+in.AIUse+in.FourthParty) / 5))
	l := int(math.Max(1, math.Round(e*(1-0.6*ce))))
	if l > 5 {
		l = 5
	}
	if m < 1 {
		m = 1
	}
	if m > 5 {
		m = 5
	}
	r := m * l
	band := "low"
	switch {
	case r >= 20:
		band = "critical"
	case r >= 10:
		band = "high"
	case r >= 5:
		band = "moderate"
	}
	return Result{
		CE: ce, Magnitude: m, Likelihood: l, Residual: r, Band: band,
		Explanation:    "R=M×L with CE from questionnaire and assurance minus open-finding penalty",
		FormulaVersion: "v1",
	}
}

func max3(a, b, c int) int {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}
