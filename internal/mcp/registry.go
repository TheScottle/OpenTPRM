package mcp

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/TheScottle/OpenTPRM/internal/authz"
)

// Tool is a static MCP tool definition (AI-010).
type Tool struct {
	Name         string
	Description  string
	Tier         int
	Scope        string
	Action       string
	ResourceType string
	InputSchema  json.RawMessage
	Handler      func(ctx context.Context, ac authz.Context, args json.RawMessage, dryRun bool) (json.RawMessage, error)
}

// Registry holds compiled-in tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

// DefaultRegistry registers T0–T3 tools from §10.3 (static).
func DefaultRegistry() *Registry {
	r := NewRegistry()
	schema := json.RawMessage(`{"type":"object","additionalProperties":false}`)
	add := func(name, desc string, tier int, scope, action, resType string) {
		n, d, sc, a, rt := name, desc, scope, action, resType
		r.Register(Tool{
			Name: n, Description: d, Tier: tier, Scope: sc, Action: a, ResourceType: rt,
			InputSchema: schema,
			Handler: func(ctx context.Context, ac authz.Context, args json.RawMessage, dryRun bool) (json.RawMessage, error) {
				return json.Marshal(map[string]any{
					"tool": n, "dry_run": dryRun, "principal": ac.PrincipalID,
					"trust": "untrusted_third_party",
				})
			},
		})
	}
	add("vendor_search", "Search vendors", 0, "tprm.read", authz.ActionVendorRead, "vendor")
	add("vendor_get", "Get vendor", 0, "tprm.read", authz.ActionVendorRead, "vendor")
	add("assessment_get", "Get assessment", 0, "tprm.read", authz.ActionAssessmentRead, "assessment")
	add("assessment_list", "List assessments", 0, "tprm.read", authz.ActionAssessmentRead, "assessment")
	add("finding_list", "List findings", 0, "tprm.read", authz.ActionFindingRead, "finding")
	add("finding_get", "Get finding", 0, "tprm.read", authz.ActionFindingRead, "finding")
	add("risk_profile_get", "Get risk profile", 0, "tprm.read", authz.ActionAssessmentRead, "risk")
	add("evidence_read_text", "Read evidence text", 1, "tprm.content.read", authz.ActionEvidenceReadContent, "evidence")
	add("evidence_search", "Search evidence", 1, "tprm.content.read", authz.ActionEvidenceReadContent, "evidence")
	add("questionnaire_responses_get", "Get questionnaire responses", 1, "tprm.content.read", authz.ActionEvidenceReadContent, "questionnaire")
	add("suggest_finding", "Suggest a finding", 2, "tprm.suggest", authz.ActionSuggest, "suggestion")
	add("suggest_soc_review_fields", "Suggest SOC review fields", 2, "tprm.suggest", authz.ActionSuggest, "suggestion")
	add("suggest_diligence_report", "Suggest diligence report", 2, "tprm.suggest", authz.ActionSuggest, "suggestion")
	add("change_request_create", "Create change request", 3, "tprm.change.request", authz.ActionChangeRequest, "change_request")
	// T4 tools are intentionally NOT registered (approve, delete, admin, export)
	return r
}
