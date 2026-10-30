package authz

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cedar-policy/cedar-go"
)

// Action names used across the system.
const (
	ActionVendorRead             = "vendor:read"
	ActionVendorWrite            = "vendor:write"
	ActionEngagementRead         = "engagement:read"
	ActionEngagementWrite        = "engagement:write"
	ActionIntakeSubmit           = "intake:submit"
	ActionAssessmentRead         = "assessment:read"
	ActionAssessmentTransition   = "assessment:transition"
	ActionAssessmentFinalize     = "assessment:finalize"
	ActionEvidenceReadContent    = "evidence:read_content"
	ActionFindingRead            = "finding:read"
	ActionFindingWrite           = "finding:write"
	ActionRiskApprove            = "risk:approve"
	ActionExceptionApprove       = "exception:approve"
	ActionAdminAny               = "admin:any"
	ActionSystemHealth           = "system:health"
	ActionExportBulk             = "export:bulk"
	ActionSuggest                = "suggestion:create"
	ActionChangeRequest          = "change_request:create"
	ActionIdentityManage         = "identity:manage"
	ActionPolicyManage           = "policy:manage"
)

// Decision is an allow/deny with policy IDs.
type Decision struct {
	Allow     bool
	PolicyIDs []string
	Reason    string
}

// Resource describes the object under authorization.
type Resource struct {
	Type           string
	ID             string
	Restricted     bool
	Allowlist      []string
	Classification string
	OwnerID        string
}

// PDP evaluates Cedar policies (IAM-001).
type PDP struct {
	mu     sync.RWMutex
	policy cedar.PolicySet
}

// NewPDP parses Cedar policy text.
func NewPDP(policyText string) (*PDP, error) {
	ps, err := cedar.NewPolicySetFromBytes("base.cedar", []byte(policyText))
	if err != nil {
		return nil, fmt.Errorf("cedar parse: %w", err)
	}
	return &PDP{policy: *ps}, nil
}

// IsAuthorized evaluates request. Default deny.
func (p *PDP) IsAuthorized(ac Context, action string, res Resource) Decision {
	p.mu.RLock()
	defer p.mu.RUnlock()

	principal := buildPrincipal(ac)
	resType := entityType(res.Type)
	if resType == "" {
		resType = "Resource"
	}
	resourceUID := cedar.NewEntityUID(cedar.EntityType(resType), cedar.String(nonEmpty(res.ID, "singleton")))

	entities := cedar.EntityMap{
		principal.UID: principal,
		resourceUID: {
			UID: resourceUID,
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"restricted":     cedar.Boolean(res.Restricted),
				"allowlist":      stringSet(res.Allowlist),
				"classification": cedar.String(res.Classification),
			}),
		},
	}

	req := cedar.Request{
		Principal: principal.UID,
		Action:    cedar.NewEntityUID("Action", cedar.String(action)),
		Resource:  resourceUID,
		Context: cedar.NewRecord(cedar.RecordMap{
			"aal":        cedar.Long(int64(ac.AAL)),
			"breakGlass": cedar.Boolean(ac.BreakGlass),
		}),
	}

	dec, diag := p.policy.IsAuthorized(entities, req)
	out := Decision{Allow: bool(dec)}
	for _, r := range diag.Reasons {
		out.PolicyIDs = append(out.PolicyIDs, string(r.PolicyID))
	}
	if !out.Allow {
		out.Reason = "deny"
		if len(diag.Errors) > 0 {
			out.Reason = diag.Errors[0].Message
		}
	}
	return out
}

func buildPrincipal(ac Context) cedar.Entity {
	var et cedar.EntityType
	switch ac.PrincipalType {
	case PrincipalAgent:
		et = "Agent"
	case PrincipalVendor:
		et = "VendorUser"
	default:
		et = "User"
	}
	uid := cedar.NewEntityUID(et, cedar.String(nonEmpty(ac.PrincipalID, "anonymous")))
	return cedar.Entity{
		UID: uid,
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"subject": cedar.String(ac.PrincipalID),
			"roles":   stringSet(ac.Roles),
			"scopes":  stringSet(ac.Scopes),
			"aal":     cedar.Long(int64(ac.AAL)),
			"privilegedCleared": cedar.Boolean(ac.PrivilegedCleared),
		}),
	}
}

func stringSet(vals []string) cedar.Value {
	elems := make([]cedar.Value, 0, len(vals))
	for _, v := range vals {
		elems = append(elems, cedar.String(v))
	}
	return cedar.NewSet(elems...)
}

func entityType(t string) string {
	if t == "" {
		return "Resource"
	}
	parts := strings.FieldsFunc(t, func(r rune) bool {
		return r == '_' || r == '-' || r == ':'
	})
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// EffectiveAgentRights intersects client ceiling and token scopes (IAM-002).
// Cedar dual-eval against the delegator is performed by the Agent Gateway.
func EffectiveAgentRights(clientCeiling, tokenScopes []string) []string {
	set := map[string]bool{}
	for _, x := range clientCeiling {
		set[x] = true
	}
	var out []string
	for _, x := range tokenScopes {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

// DualAuthorize requires both agent and delegator evaluations to allow (IAM-002).
func DualAuthorize(pdp *PDP, agent, delegator Context, action string, res Resource) Decision {
	a := pdp.IsAuthorized(agent, action, res)
	if !a.Allow {
		return a
	}
	d := pdp.IsAuthorized(delegator, action, res)
	if !d.Allow {
		return Decision{Allow: false, Reason: "delegator deny", PolicyIDs: d.PolicyIDs}
	}
	return Decision{Allow: true, PolicyIDs: append(a.PolicyIDs, d.PolicyIDs...)}
}
