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
	rows := []row{
		{
			name: "analyst_reads_vendor",
			ac: authz.Context{PrincipalID: "a1", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"risk_analyst"}, AAL: 2},
			action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: true,
		},
		{
			name: "agent_cannot_approve",
			ac: authz.Context{PrincipalID: "ag1", PrincipalType: authz.PrincipalAgent, Roles: []string{}, Scopes: []string{"tprm.read", "tprm.change.request"}, AAL: 2},
			action: authz.ActionRiskApprove, res: authz.Resource{Type: "risk", ID: "r1"}, allow: false,
		},
		{
			name: "restricted_denies_non_allowlist",
			ac: authz.Context{PrincipalID: "a1", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"risk_analyst"}, AAL: 2},
			action: authz.ActionVendorRead, res: authz.Resource{Type: "vendor", ID: "secret", Restricted: true, Allowlist: []string{"other"}}, allow: false,
		},
		{
			name: "viewer_cannot_write",
			ac: authz.Context{PrincipalID: "v", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"viewer"}, AAL: 2},
			action: authz.ActionVendorWrite, res: authz.Resource{Type: "vendor", ID: "v1"}, allow: false,
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
