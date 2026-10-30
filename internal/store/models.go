package store

// Vendor is a third_party row (INV-001).
type Vendor struct {
	ID               string `json:"id"`
	LegalName        string `json:"legal_name"`
	AliasesJSON      string `json:"aliases_json,omitempty"`
	LEI              string `json:"lei,omitempty"`
	Country          string `json:"country,omitempty"`
	HQAddress        string `json:"hq_address,omitempty"`
	DomainsJSON      string `json:"domains_json,omitempty"`
	ParentID         string `json:"parent_id,omitempty"`
	UltimateParentID string `json:"ultimate_parent_id,omitempty"`
	PublicPrivate    string `json:"public_private,omitempty"`
	Regulated        bool   `json:"regulated,omitempty"`
	Status           string `json:"status"`
	Tier             int    `json:"tier"`
	TagsJSON         string `json:"tags_json,omitempty"`
	Classification   string `json:"classification"`
	Restricted       bool   `json:"restricted"`
	AllowlistJSON    string `json:"allowlist_json"`
	CreatedBy        string `json:"created_by"`
	UpdatedBy        string `json:"updated_by"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
	RowVersion       int64  `json:"row_version,omitempty"`
}

// Engagement is an engagement row (INV-003).
type Engagement struct {
	ID                    string `json:"id"`
	ThirdPartyID          string `json:"third_party_id"`
	ServiceDescription    string `json:"service_description,omitempty"`
	ServiceCategory       string `json:"service_category,omitempty"`
	RelationshipOwner     string `json:"relationship_owner"`
	BusinessUnit          string `json:"business_unit,omitempty"`
	ClientRef             string `json:"client_ref,omitempty"`
	MatterRef             string `json:"matter_ref,omitempty"`
	ContractRefsJSON      string `json:"contract_refs_json,omitempty"`
	StartDate             string `json:"start_date,omitempty"`
	EndDate               string `json:"end_date,omitempty"`
	RenewalDate           string `json:"renewal_date,omitempty"`
	SpendBand             string `json:"spend_band,omitempty"`
	DataTypesJSON         string `json:"data_types_json,omitempty"`
	HighestClassification string `json:"highest_classification,omitempty"`
	DataVolumeBand        string `json:"data_volume_band,omitempty"`
	DataLocationsJSON     string `json:"data_locations_json,omitempty"`
	AccessTypesJSON       string `json:"access_types_json,omitempty"`
	IntegrationMethodsJSON string `json:"integration_methods_json,omitempty"`
	OperationalCriticality int   `json:"operational_criticality,omitempty"`
	Substitutability      int    `json:"substitutability,omitempty"`
	VendorAIUse           string `json:"vendor_ai_use,omitempty"`
	VendorAIDescription   string `json:"vendor_ai_description,omitempty"`
	SubcontractorUse      bool   `json:"subcontractor_use,omitempty"`
	InherentTier          int    `json:"inherent_tier,omitempty"`
	NextActionDue         string `json:"next_action_due,omitempty"`
	CreatedBy             string `json:"created_by"`
	UpdatedBy             string `json:"updated_by"`
	CreatedAt             string `json:"created_at,omitempty"`
	UpdatedAt             string `json:"updated_at,omitempty"`
	RowVersion            int64  `json:"row_version,omitempty"`
}

// VendorContact is a vendor_contacts row (INV-004).
type VendorContact struct {
	ID           string `json:"id"`
	ThirdPartyID string `json:"third_party_id"`
	Role         string `json:"role"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	LastVerified string `json:"last_verified,omitempty"`
	CreatedBy    string `json:"created_by"`
	UpdatedBy    string `json:"updated_by"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

// FourthPartyLink links vendors in the fourth-party graph (INV-005).
type FourthPartyLink struct {
	ID               string `json:"id"`
	FromThirdPartyID string `json:"from_third_party_id"`
	ToThirdPartyID   string `json:"to_third_party_id"`
	Role             string `json:"role"`
	Source           string `json:"source"`
	DataAccess       string `json:"data_access,omitempty"`
	CreatedBy        string `json:"created_by"`
	UpdatedBy        string `json:"updated_by"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// HistoryEntry is an object_history row (INV-007).
type HistoryEntry struct {
	ID         string `json:"id"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	Actor      string `json:"actor"`
	TS         string `json:"ts"`
	BeforeJSON string `json:"before_json"`
	AfterJSON  string `json:"after_json"`
	Reason     string `json:"reason"`
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

// ImportRowResult is a per-row bulk import outcome (INV-008).
type ImportRowResult struct {
	Row     int    `json:"row"`
	OK      bool   `json:"ok"`
	VendorID string `json:"vendor_id,omitempty"`
	Error   string `json:"error,omitempty"`
}
