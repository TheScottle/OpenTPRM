package store

// Vendor is a third_party row.
type Vendor struct {
	ID             string `json:"id"`
	LegalName      string `json:"legal_name"`
	Status         string `json:"status"`
	Tier           int    `json:"tier"`
	Classification string `json:"classification"`
	Restricted     bool   `json:"restricted"`
	AllowlistJSON  string `json:"allowlist_json"`
	CreatedBy      string `json:"created_by"`
	UpdatedBy      string `json:"updated_by"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type Intake struct {
	ID               string  `json:"id"`
	EngagementID     string  `json:"engagement_id"`
	AnswersJSON      string  `json:"answers_json"`
	FactorScoresJSON string  `json:"factor_scores_json"`
	WeightedScore    float64 `json:"weighted_score"`
	Tier             int     `json:"tier"`
	PlanJSON         string  `json:"plan_json"`
	Status           string  `json:"status"`
	CreatedBy        string  `json:"created_by"`
	UpdatedBy        string  `json:"updated_by"`
}

type Assessment struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	Type         string `json:"type"`
	State        string `json:"state"`
	PlanJSON     string `json:"plan_json"`
	CreatedBy    string `json:"created_by"`
	UpdatedBy    string `json:"updated_by"`
}

type Template struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type Evidence struct {
	ID             string `json:"id"`
	EngagementID   string `json:"engagement_id"`
	Status         string `json:"status"`
	EvidenceType   string `json:"evidence_type"`
	Classification string `json:"classification"`
	LicenseTag     string `json:"license_tag"`
}

type Finding struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	FindingType  string `json:"finding_type"`
}
