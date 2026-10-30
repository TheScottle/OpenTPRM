package authz_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAuthorizationMatrixHarness(t *testing.T) {
	text, err := policies.Base()
	if err != nil {
		t.Fatal(err)
	}
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatalf("cedar parse: %v", err)
	}

	type row struct {
		name   string
		ac     authz.Context
		action string
		res    authz.Resource
		allow  bool
	}
	analyst := authz.Context{PrincipalID: "a1", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"risk_analyst"}, AAL: 2}
	viewer := authz.Context{PrincipalID: "v", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"viewer"}, AAL: 2}
	rows := []row{
		{name: "analyst_reads_vendor", ac: analyst, action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "analyst_writes_vendor", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "analyst_engagement_read", ac: analyst, action: authz.ActionEngagementRead, res: authz.Resource{Type: "engagement", ID: "e1"}, allow: true},
		{name: "analyst_engagement_write", ac: analyst, action: authz.ActionEngagementWrite, res: authz.Resource{Type: "engagement", ID: "e1"}, allow: true},
		{name: "analyst_intake_submit", ac: analyst, action: authz.ActionIntakeSubmit, res: authz.Resource{Type: "intake", ID: "i1"}, allow: true},
		{name: "analyst_assessment_read", ac: analyst, action: authz.ActionAssessmentRead, res: authz.Resource{Type: "assessment", ID: "as1"}, allow: true},
		{name: "analyst_assessment_transition", ac: analyst, action: authz.ActionAssessmentTransition, res: authz.Resource{Type: "assessment", ID: "as1"}, allow: true},
		{name: "analyst_contact_write_as_vendor_write", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "analyst_fourth_party_write", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "fourth_party_link", ID: "l1"}, allow: true},
		{name: "analyst_history_read", ac: analyst, action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "analyst_csv_import", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "*"}, allow: true},
		{name: "analyst_merge", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "analyst_custom_fields", ac: analyst, action: authz.ActionVendorWrite, res: authz.Resource{Type: "custom_field", ID: "*"}, allow: true},
		{name: "analyst_upload_as_engagement_write", ac: analyst, action: authz.ActionEngagementWrite, res: authz.Resource{Type: "evidence", ID: "*"}, allow: true},
		{name: "analyst_evidence_read_aal2", ac: analyst, action: authz.ActionEvidenceReadContent, res: authz.Resource{Type: "evidence", ID: "e1"}, allow: true},
		{name: "viewer_cannot_upload", ac: viewer, action: authz.ActionEngagementWrite, res: authz.Resource{Type: "evidence", ID: "*"}, allow: false},
		{name: "viewer_reads_vendor", ac: viewer, action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true},
		{name: "viewer_cannot_write", ac: viewer, action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: false},
		{name: "viewer_cannot_intake_submit", ac: viewer, action: authz.ActionIntakeSubmit, res: authz.Resource{Type: "intake", ID: "i1"}, allow: false},
		{name: "viewer_cannot_engagement_write", ac: viewer, action: authz.ActionEngagementWrite, res: authz.Resource{Type: "engagement", ID: "e1"}, allow: false},
		{
			name: "agent_cannot_approve",
			ac: authz.Context{PrincipalID: "ag1", PrincipalType: authz.PrincipalAgent, Roles: []string{}, Scopes: []string{"tprm.read", "tprm.change.request"}, AAL: 2},
			action: authz.ActionRiskApprove, res: authz.Resource{Type: "risk", ID: "r1"}, allow: false,
		},
		{
			name: "agent_reads_with_scope",
			ac: authz.Context{PrincipalID: "ag1", PrincipalType: authz.PrincipalAgent, Scopes: []string{"tprm.read"}, AAL: 2},
			action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true,
		},
		{
			name: "agent_cannot_intake_submit",
			ac: authz.Context{PrincipalID: "ag1", PrincipalType: authz.PrincipalAgent, Scopes: []string{"tprm.read"}, AAL: 2},
			action: authz.ActionIntakeSubmit, res: authz.Resource{Type: "intake", ID: "i1"}, allow: false,
		},
		{
			name: "restricted_denies_non_allowlist",
			ac: analyst, action: authz.ActionVendorRead,
			res: authz.Resource{Type: "vendor", ID: "secret", Restricted: true, Allowlist: []string{"other"}}, allow: false,
		},
		{
			name: "approver_can_approve",
			ac: authz.Context{PrincipalID: "ap", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"approver"}, AAL: 2},
			action: authz.ActionExceptionApprove, res: authz.Resource{Type: "exception", ID: "x1"}, allow: true,
		},
		{
			name: "relationship_owner_intake_submit",
			ac: authz.Context{PrincipalID: "ro", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"relationship_owner"}, AAL: 2},
			action: authz.ActionIntakeSubmit, res: authz.Resource{Type: "intake", ID: "i1"}, allow: true,
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			d := pdp.IsAuthorized(r.ac, r.action, r.res)
			if d.Allow != r.allow {
				t.Fatalf("allow=%v want %v reason=%s policies=%v", d.Allow, r.allow, d.Reason, d.PolicyIDs)
			}
		})
	}
}

func TestEffectiveAgentRights(t *testing.T) {
	got := authz.EffectiveAgentRights([]string{"tprm.read", "tprm.suggest"}, []string{"tprm.read", "tprm.change.request"})
	if len(got) != 1 || got[0] != "tprm.read" {
		t.Fatalf("got %v", got)
	}
}
