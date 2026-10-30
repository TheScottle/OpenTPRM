package gateway_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/gateway"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAI_032_BudgetWiredOnGateway(t *testing.T) {
	text, err := policies.Base()
	if err != nil {
		t.Fatal(err)
	}
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatal(err)
	}
	reg := mcp.NewRegistry()
	reg.Register(mcp.Tool{
		Name: "vendor_get", Description: "Get vendor", Tier: 0, Scope: "tprm.read",
		Action: authz.ActionVendorRead, ResourceType: "vendor",
		InputSchema: json.RawMessage(`{}`),
		Handler: func(ctx context.Context, ac authz.Context, args json.RawMessage, dryRun bool) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"ok": true})
		},
	})
	gw := gateway.New(pdp, reg)
	gw.Budgets = gateway.NewBudgetTracker(gateway.BudgetLimits{RequestsPerMinute: 2, ToolCallsPerHour: 100, SuggestionsPerHour: 10})
	agent := authz.Context{
		PrincipalID: "ag", PrincipalType: authz.PrincipalAgent, ClientID: "c1",
		Scopes: []string{"tprm.read"}, AAL: 2, DelegatorID: "user1",
	}
	delegator := authz.Context{
		PrincipalID: "user1", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"risk_analyst"}, AAL: 2,
	}
	for i := 0; i < 2; i++ {
		res := gw.Call(context.Background(), agent, delegator, "vendor_get", nil)
		if !res.OK {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	res := gw.Call(context.Background(), agent, delegator, "vendor_get", nil)
	if res.OK || res.Status != 429 {
		t.Fatalf("expected budget 429, got %+v", res)
	}
}
