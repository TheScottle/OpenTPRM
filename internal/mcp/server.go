package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/TheScottle/OpenTPRM/internal/authz"
)

// ProtocolVersion for MCP 2026-07-28.
const ProtocolVersion = "2026-07-28"

// Server is a stateless Streamable HTTP MCP endpoint (AI-001).
type Server struct {
	Gateway interface {
		Call(ctx interface{ Done() <-chan struct{} }, agent, delegator authz.Context, tool string, args json.RawMessage) interface{}
		VisibleTools(agent authz.Context) []Tool
	}
	// Concrete gateway adapter set by HTTP layer
	CallFn   func(r *http.Request, agent, delegator authz.Context, tool string, args json.RawMessage) (json.RawMessage, int, string)
	ListFn   func(agent authz.Context) []Tool
	Origins  []string
	Tasks    *TaskStore
}

// ServeHTTP handles /mcp (stateless).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !originAllowed(origin, s.Origins) {
		http.Error(w, "origin refused", http.StatusForbidden)
		return
	}

	proto := r.Header.Get("MCP-Protocol-Version")
	methodHdr := r.Header.Get("Mcp-Method")
	nameHdr := r.Header.Get("Mcp-Name")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var rpc struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// AI-002 / AT-09: header/body consistency
	if methodHdr != "" && rpc.Method != "" && methodHdr != rpc.Method {
		writeRPCError(w, rpc.ID, -32600, "Mcp-Method header/body mismatch")
		return
	}
	if rpc.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(rpc.Params, &p)
		if nameHdr != "" && p.Name != "" && nameHdr != p.Name {
			writeRPCError(w, rpc.ID, -32600, "Mcp-Name header/body mismatch")
			return
		}
	}
	if proto != "" && proto != ProtocolVersion {
		writeRPCError(w, rpc.ID, -32600, "unsupported protocol version")
		return
	}

	agent := authFromRequest(r)
	delegator := agent
	if agent.DelegatorID != "" {
		delegator.PrincipalID = agent.DelegatorID
		delegator.PrincipalType = authz.PrincipalWorkforce
	}

	switch rpc.Method {
	case "server/discover", "initialize":
		writeRPC(w, rpc.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{},
				"tasks": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": "opentprm", "version": "dev"},
		})
	case "tasks/get":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rpc.Params, &p)
		if s.Tasks == nil {
			writeRPCError(w, rpc.ID, -32603, "tasks not configured")
			return
		}
		task, ok := s.Tasks.Get(p.ID, agent.PrincipalID)
		if !ok {
			writeRPCError(w, rpc.ID, -32004, "task not found")
			return
		}
		writeRPC(w, rpc.ID, task)
	case "tasks/update":
		var p struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Progress int    `json:"progress"`
		}
		_ = json.Unmarshal(rpc.Params, &p)
		if s.Tasks == nil {
			writeRPCError(w, rpc.ID, -32603, "tasks not configured")
			return
		}
		task, ok := s.Tasks.UpdateProgress(p.ID, agent.PrincipalID, p.Status, p.Progress)
		if !ok {
			writeRPCError(w, rpc.ID, -32004, "task not found")
			return
		}
		writeRPC(w, rpc.ID, task)
	case "tasks/cancel":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rpc.Params, &p)
		if s.Tasks == nil {
			writeRPCError(w, rpc.ID, -32603, "tasks not configured")
			return
		}
		task, ok := s.Tasks.Cancel(p.ID, agent.PrincipalID)
		if !ok {
			writeRPCError(w, rpc.ID, -32004, "task not found")
			return
		}
		writeRPC(w, rpc.ID, task)
	case "tools/list":
		tools := []map[string]any{}
		if s.ListFn != nil {
			for _, t := range s.ListFn(agent) {
				tools = append(tools, map[string]any{
					"name": t.Name, "description": t.Description, "inputSchema": json.RawMessage(t.InputSchema),
					"annotations": map[string]any{"readOnlyHint": t.Tier <= 1, "destructiveHint": false, "openWorldHint": false},
				})
			}
		}
		writeRPC(w, rpc.ID, map[string]any{"tools": tools, "cacheScope": "private", "ttlMs": 300000})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(rpc.Params, &p)
		if s.CallFn == nil {
			writeRPCError(w, rpc.ID, -32603, "gateway not configured")
			return
		}
		raw, status, errMsg := s.CallFn(r, agent, delegator, p.Name, p.Arguments)
		if errMsg != "" {
			code := -32000
			if status == 403 {
				code = -32003
			}
			writeRPCError(w, rpc.ID, code, errMsg)
			return
		}
		writeRPC(w, rpc.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(raw)}},
			"structuredContent": json.RawMessage(raw),
		})
	default:
		writeRPCError(w, rpc.ID, -32601, "method not found")
	}
}

func authFromRequest(r *http.Request) authz.Context {
	uid := r.Header.Get("X-OpenTPRM-User")
	if uid == "" {
		uid = "agent"
	}
	scopes := strings.Fields(r.Header.Get("X-OpenTPRM-Scopes"))
	return authz.Context{
		PrincipalID:   uid,
		PrincipalType: authz.PrincipalAgent,
		ClientID:      r.Header.Get("X-OpenTPRM-Client"),
		DelegatorID:   r.Header.Get("X-OpenTPRM-Delegator"),
		Scopes:        scopes,
		Roles:         []string{},
		AAL:           2,
	}
}

func originAllowed(origin string, allow []string) bool {
	if len(allow) == 0 {
		// deny-by-default for browser origins when list empty — allow non-browser (no Origin)
		return false
	}
	for _, a := range allow {
		if a == origin {
			return true
		}
	}
	return false
}

func writeRPC(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors still 200
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg},
	})
}
