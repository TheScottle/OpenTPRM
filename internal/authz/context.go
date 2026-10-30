package authz

import (
	"context"
	"time"
)

// Context is required by every repository method (SEC-AZ-001).
// Handlers construct it after authentication; store methods refuse a zero value.
type Context struct {
	PrincipalID   string
	PrincipalType PrincipalType
	Roles         []string
	DelegatorID   string // set for agents
	ClientID      string // agent client id
	Scopes        []string
	AAL           int
	SessionID     string
	ClassificationCeiling string
	BreakGlass    bool
	PrivilegedCleared bool
	VendorScope   string // vendor principal namespace
	IP            string
	TraceID       string
	StepUpAt      time.Time
}

type PrincipalType string

const (
	PrincipalWorkforce PrincipalType = "workforce"
	PrincipalVendor    PrincipalType = "vendor"
	PrincipalAgent     PrincipalType = "agent"
	PrincipalService   PrincipalType = "service"
	PrincipalSystem    PrincipalType = "system"
)

type ctxKey struct{}

func WithContext(ctx context.Context, ac Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, ac)
}

func FromContext(ctx context.Context) (Context, bool) {
	ac, ok := ctx.Value(ctxKey{}).(Context)
	return ac, ok
}

// Valid reports whether the authorization context is usable for store calls.
func (c Context) Valid() bool {
	return c.PrincipalID != "" && c.PrincipalType != ""
}

// Authenticated reports a real workforce/agent principal (not anonymous).
// Cookie sessions and AllowDevHeaders test principals both qualify when PrincipalID is set.
func (c Context) Authenticated() bool {
	return c.PrincipalID != "" && c.PrincipalID != "anonymous" && c.PrincipalType != ""
}

// HasRole reports whether the principal holds the named role.
func (c Context) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// StepUpFresh reports whether WebAuthn step-up occurred within the last 5 minutes.
func (c Context) StepUpFresh() bool {
	if c.StepUpAt.IsZero() {
		return false
	}
	return time.Since(c.StepUpAt) <= 5*time.Minute
}
