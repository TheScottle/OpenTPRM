package seed

import (
	"context"

	"github.com/TheScottle/OpenTPRM/internal/config"
)

// DemoGraph is a richer Sterling & Vance development-only seed graph (OPS-004).
type DemoGraph struct {
	Org         DemoVendor        `json:"org"`
	Vendors     []DemoTPVendor    `json:"vendors"`
	Contacts    []DemoContact     `json:"contacts"`
	Engagements []DemoEngagement  `json:"engagements"`
	AnswerKeys  []DemoAnswer      `json:"answer_library"`
	Notes       string            `json:"notes"`
}

// DemoTPVendor is a third-party row in the demo graph.
type DemoTPVendor struct {
	ID             string `json:"id"`
	LegalName      string `json:"legal_name"`
	TradeName      string `json:"trade_name,omitempty"`
	Tier           int    `json:"tier"`
	Status         string `json:"status"`
	Country        string `json:"country,omitempty"`
	Classification string `json:"classification"`
}

// DemoContact is a demo vendor contact.
type DemoContact struct {
	VendorID string `json:"id,omitempty"`
	VendorRef string `json:"vendor_id"`
	Role     string `json:"role"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

// DemoEngagement is a demo engagement stub.
type DemoEngagement struct {
	ID                 string `json:"id"`
	VendorRef          string `json:"vendor_id"`
	ServiceDescription string `json:"service_description"`
	RelationshipOwner  string `json:"relationship_owner"`
	BusinessUnit       string `json:"business_unit"`
}

// DemoAnswer is a demo answer-library entry.
type DemoAnswer struct {
	VendorRef   string `json:"vendor_id"`
	QuestionKey string `json:"question_key"`
	AnswerJSON  string `json:"answer_json"`
}

// DemoGraphSeed returns the Sterling & Vance LLP development graph.
// Callers MUST gate with AllowDemo; never apply under production mode.
func DemoGraphSeed() DemoGraph {
	return DemoGraph{
		Org:   DemoOrg(),
		Notes: "OPS-004 richer Sterling & Vance demo; development/test only",
		Vendors: []DemoTPVendor{
			{
				ID: "demo-sv-cloud", LegalName: "Northwind Cloud Hosting LLC", TradeName: "Northwind Cloud",
				Tier: 1, Status: "active", Country: "US", Classification: "Confidential",
			},
			{
				ID: "demo-sv-payroll", LegalName: "Ledgerline Payroll Inc.", TradeName: "Ledgerline",
				Tier: 2, Status: "active", Country: "US", Classification: "Client-Confidential",
			},
			{
				ID: "demo-sv-edisc", LegalName: "Harbor eDiscovery Partners", TradeName: "Harbor eDisc",
				Tier: 1, Status: "active", Country: "US", Classification: "Privileged",
			},
		},
		Contacts: []DemoContact{
			{VendorRef: "demo-sv-cloud", Role: "security", Name: "Avery Chen", Email: "security@northwind.example"},
			{VendorRef: "demo-sv-payroll", Role: "account", Name: "Jordan Blake", Email: "accounts@ledgerline.example"},
			{VendorRef: "demo-sv-edisc", Role: "legal", Name: "Sam Ortiz", Email: "counsel@harbor.example"},
		},
		Engagements: []DemoEngagement{
			{
				ID: "demo-eng-cloud", VendorRef: "demo-sv-cloud",
				ServiceDescription: "Matter DMS hosting for Sterling & Vance",
				RelationshipOwner:  "ops-risk@sv.example", BusinessUnit: "Information Security",
			},
			{
				ID: "demo-eng-payroll", VendorRef: "demo-sv-payroll",
				ServiceDescription: "Firm payroll and benefits administration",
				RelationshipOwner:  "hr-ops@sv.example", BusinessUnit: "People Operations",
			},
			{
				ID: "demo-eng-edisc", VendorRef: "demo-sv-edisc",
				ServiceDescription: "Litigation hold and eDiscovery processing",
				RelationshipOwner:  "lit-support@sv.example", BusinessUnit: "Litigation Support",
			},
		},
		AnswerKeys: []DemoAnswer{
			{VendorRef: "demo-sv-cloud", QuestionKey: "IAM-01", AnswerJSON: `"SSO via OIDC; MFA required"`},
			{VendorRef: "demo-sv-cloud", QuestionKey: "ENC-02", AnswerJSON: `"AES-256 at rest; TLS 1.3 in transit"`},
			{VendorRef: "demo-sv-payroll", QuestionKey: "PRI-01", AnswerJSON: `"SOC 2 Type II available under NDA"`},
			{VendorRef: "demo-sv-edisc", QuestionKey: "LEG-03", AnswerJSON: `"Data residency US-only; counsel-directed holds"`},
		},
	}
}

// ApplyDemoGraph applies the richer graph when demo seed is requested and allowed for mode.
func ApplyDemoGraph(ctx context.Context, mode config.Mode, apply func(context.Context, DemoGraph) error) error {
	if err := AllowDemo(mode); err != nil {
		return err
	}
	if !Requested() {
		return nil
	}
	if apply == nil {
		return nil
	}
	return apply(ctx, DemoGraphSeed())
}
