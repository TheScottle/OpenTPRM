package authz_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAT_02_RestrictedRecord404Semantics(t *testing.T) {
	text, err := policies.Base()
	if err != nil {
		t.Fatal(err)
	}
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatal(err)
	}
	analyst := authz.Context{
		PrincipalID: "analyst-a", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"risk_analyst"}, AAL: 2,
	}
	res := authz.Resource{Type: "vendor", ID: "restricted-1", Restricted: true, Allowlist: []string{"other-user"}}
	d := pdp.IsAuthorized(analyst, authz.ActionVendorRead, res)
	if d.Allow {
		t.Fatal("AT-02: non-allowlisted analyst must be denied")
	}
	// Agent of that analyst also denied
	agent := authz.Context{
		PrincipalID: "agent-1", PrincipalType: authz.PrincipalAgent,
		DelegatorID: "analyst-a", Scopes: []string{"tprm.read", "tprm.content.read"}, AAL: 2,
	}
	d2 := authz.DualAuthorize(pdp, agent, analyst, authz.ActionEvidenceReadContent, res)
	if d2.Allow {
		t.Fatal("AT-02: agent must also be denied on restricted record")
	}
}
