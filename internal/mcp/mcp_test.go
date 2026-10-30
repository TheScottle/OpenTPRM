package mcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAT_09_HeaderBodyNameMismatch(t *testing.T) {
	s := &mcp.Server{
		ListFn: func(agent authz.Context) []mcp.Tool { return nil },
		CallFn: func(r *http.Request, agent, delegator authz.Context, tool string, args json.RawMessage) (json.RawMessage, int, string) {
			return nil, 500, "should not be called"
		},
		Origins: nil,
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vendor_get","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "vendor_search") // mismatch
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Fatalf("AT-09: expected error, got %s", rr.Body.String())
	}
}

func TestAI_005_TasksExtensionStubs(t *testing.T) {
	store := mcp.NewTaskStore()
	task := store.Create("agent", "evidence_search")
	s := &mcp.Server{Tasks: store, Origins: nil}
	body := `{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"` + task.ID + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OpenTPRM-User", "agent")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != nil {
		t.Fatalf("tasks/get: %s", rr.Body.String())
	}
	// Other principal cannot read.
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-OpenTPRM-User", "other")
	rr2 := httptest.NewRecorder()
	s.ServeHTTP(rr2, req2)
	var resp2 map[string]any
	_ = json.Unmarshal(rr2.Body.Bytes(), &resp2)
	if resp2["error"] == nil {
		t.Fatal("AI-005: other principal must not get task")
	}
	cancelBody := `{"jsonrpc":"2.0","id":3,"method":"tasks/cancel","params":{"id":"` + task.ID + `"}}`
	req3 := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(cancelBody))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-OpenTPRM-User", "agent")
	rr3 := httptest.NewRecorder()
	s.ServeHTTP(rr3, req3)
	var resp3 map[string]any
	_ = json.Unmarshal(rr3.Body.Bytes(), &resp3)
	result, _ := resp3["result"].(map[string]any)
	if result["status"] != mcp.TaskCancelled {
		t.Fatalf("cancel: %s", rr3.Body.String())
	}
}

func TestAT_03_NoApproveToolListed(t *testing.T) {
	reg := mcp.DefaultRegistry()
	for _, ttool := range reg.List() {
		if ttool.Name == "risk_approve" || ttool.Action == authz.ActionRiskApprove {
			t.Fatalf("T4 approve tool must not be registered: %s", ttool.Name)
		}
	}
	text, _ := policies.Base()
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatal(err)
	}
	agent := authz.Context{PrincipalID: "ag", PrincipalType: authz.PrincipalAgent, Scopes: []string{"tprm.read", "tprm.change.request"}, AAL: 2}
	d := pdp.IsAuthorized(agent, authz.ActionRiskApprove, authz.Resource{Type: "risk", ID: "1"})
	if d.Allow {
		t.Fatal("AT-03: agent must not approve")
	}
}
