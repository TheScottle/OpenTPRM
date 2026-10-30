package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
)

const (
	TierT0 = 0
	TierT1 = 1
	TierT2 = 2
	TierT3 = 3
	TierT4 = 4
)

// Gateway is the Agent Gateway (authenticate → authorize → validate → execute → audit).
type Gateway struct {
	PDP      *authz.PDP
	Registry *mcp.Registry
	mu       sync.Mutex
	killed   map[string]bool
	aiOff    bool
}

func New(pdp *authz.PDP, reg *mcp.Registry) *Gateway {
	return &Gateway{PDP: pdp, Registry: reg, killed: map[string]bool{}}
}

func (g *Gateway) KillClient(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.killed[id] = true
}

func (g *Gateway) SetGlobalAIOff(off bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.aiOff = off
}

// CallResult is returned to MCP/REST agent callers.
type CallResult struct {
	OK     bool
	Error  string
	Status int
	Result json.RawMessage
	DryRun bool
}

// Call runs a tool with dual authorization.
func (g *Gateway) Call(ctx context.Context, agent, delegator authz.Context, toolName string, args json.RawMessage) CallResult {
	g.mu.Lock()
	off, killed := g.aiOff, g.killed[agent.ClientID]
	g.mu.Unlock()
	if off {
		return CallResult{Error: "AI off", Status: 503}
	}
	if killed {
		return CallResult{Error: "client suspended", Status: 403}
	}
	tool, ok := g.Registry.Get(toolName)
	if !ok {
		return CallResult{Error: "unknown tool", Status: 404}
	}
	if tool.Tier >= TierT4 {
		return CallResult{Error: "T4 prohibited", Status: 403}
	}
	if tool.Scope != "" && !has(agent.Scopes, tool.Scope) {
		return CallResult{Error: "insufficient_scope", Status: 403}
	}
	dec := authz.DualAuthorize(g.PDP, agent, delegator, tool.Action, authz.Resource{Type: tool.ResourceType, ID: "*"})
	if !dec.Allow {
		return CallResult{Error: "authorization denied", Status: 403}
	}
	dry := false
	var m map[string]any
	if len(args) > 0 {
		_ = json.Unmarshal(args, &m)
		if v, ok := m["dry_run"].(bool); ok {
			dry = v
		}
	}
	out, err := tool.Handler(ctx, agent, args, dry)
	if err != nil {
		return CallResult{Error: err.Error(), Status: 422}
	}
	return CallResult{OK: true, Result: out, DryRun: dry, Status: 200}
}

func (g *Gateway) VisibleTools(agent authz.Context) []mcp.Tool {
	var out []mcp.Tool
	for _, t := range g.Registry.List() {
		if t.Tier >= TierT4 {
			continue
		}
		if t.Scope != "" && !has(agent.Scopes, t.Scope) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func has(ss []string, v string) bool {
	for _, s := range ss {
		if strings.TrimSpace(s) == v {
			return true
		}
	}
	return false
}
