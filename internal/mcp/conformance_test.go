package mcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
)

func TestMCP_InitializeAndDiscoverConformance(t *testing.T) {
	s := &mcp.Server{
		ListFn: func(agent authz.Context) []mcp.Tool { return mcp.DefaultRegistry().List() },
		Origins: nil,
	}
	for _, method := range []string{"initialize", "server/discover"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if resp["error"] != nil {
			t.Fatalf("%s error: %s", method, rr.Body.String())
		}
		result, _ := resp["result"].(map[string]any)
		if result["protocolVersion"] != mcp.ProtocolVersion {
			t.Fatalf("%s protocol: %v", method, result["protocolVersion"])
		}
		caps, _ := result["capabilities"].(map[string]any)
		if caps["tools"] == nil || caps["tasks"] == nil {
			t.Fatalf("%s capabilities incomplete: %v", method, caps)
		}
		info, _ := result["serverInfo"].(map[string]any)
		if info["name"] != "opentprm" {
			t.Fatalf("%s serverInfo: %v", method, info)
		}
	}
}

func TestMCP_ToolsListShape(t *testing.T) {
	s := &mcp.Server{
		ListFn: func(agent authz.Context) []mcp.Tool {
			return []mcp.Tool{{Name: "vendor_get", Description: "get", InputSchema: []byte(`{}`), Tier: 1}}
		},
	}
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	result, _ := resp["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools: %v", result)
	}
	tool, _ := tools[0].(map[string]any)
	ann, _ := tool["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true {
		t.Fatalf("annotations: %v", ann)
	}
	if result["cacheScope"] != "private" {
		t.Fatalf("cacheScope: %v", result["cacheScope"])
	}
}
