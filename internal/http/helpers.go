package httpserver

import (
	"context"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

func rContext(ac authz.Context) context.Context {
	return authz.WithContext(context.Background(), ac)
}

func auditDecision(ac authz.Context, action string, res authz.Resource, d authz.Decision) audit.Event {
	decision := "deny"
	if d.Allow {
		decision = "allow"
	}
	return audit.Event{
		Actor:         ac.PrincipalID,
		Delegator:     ac.DelegatorID,
		PrincipalType: string(ac.PrincipalType),
		Action:        action,
		ResourceType:  res.Type,
		ResourceID:    res.ID,
		Decision:      decision,
		PolicyIDs:     d.PolicyIDs,
		TraceID:       ac.TraceID,
		IP:            ac.IP,
	}
}
