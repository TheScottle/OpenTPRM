package gateway

import (
	"sync"
	"time"
)

// BudgetLimits are per-client / per-delegator caps (AI-032).
type BudgetLimits struct {
	RequestsPerMinute int
	ToolCallsPerHour  int
	SuggestionsPerHour int
}

// DefaultBudgetLimits matches deploy/config.example defaults.
func DefaultBudgetLimits() BudgetLimits {
	return BudgetLimits{
		RequestsPerMinute:  60,
		ToolCallsPerHour:   600,
		SuggestionsPerHour: 120,
	}
}

type budgetWindow struct {
	minuteStart time.Time
	hourStart   time.Time
	requests    int
	toolCalls   int
	suggestions int
}

// BudgetTracker enforces AI-032 budgets in the Agent Gateway.
type BudgetTracker struct {
	mu      sync.Mutex
	limits  BudgetLimits
	byKey   map[string]*budgetWindow
}

// NewBudgetTracker constructs a tracker with the given limits.
func NewBudgetTracker(limits BudgetLimits) *BudgetTracker {
	if limits.RequestsPerMinute <= 0 {
		limits.RequestsPerMinute = DefaultBudgetLimits().RequestsPerMinute
	}
	if limits.ToolCallsPerHour <= 0 {
		limits.ToolCallsPerHour = DefaultBudgetLimits().ToolCallsPerHour
	}
	if limits.SuggestionsPerHour <= 0 {
		limits.SuggestionsPerHour = DefaultBudgetLimits().SuggestionsPerHour
	}
	return &BudgetTracker{limits: limits, byKey: map[string]*budgetWindow{}}
}

// Allow records a tool call against subject (client or delegator id) and returns false when over budget.
func (b *BudgetTracker) Allow(subject string, isSuggestion bool) (ok bool, reason string) {
	if b == nil {
		return true, ""
	}
	now := time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.byKey[subject]
	if w == nil {
		w = &budgetWindow{minuteStart: now, hourStart: now}
		b.byKey[subject] = w
	}
	if now.Sub(w.minuteStart) >= time.Minute {
		w.minuteStart = now
		w.requests = 0
	}
	if now.Sub(w.hourStart) >= time.Hour {
		w.hourStart = now
		w.toolCalls = 0
		w.suggestions = 0
	}
	if w.requests >= b.limits.RequestsPerMinute {
		return false, "budget_exceeded: requests_per_minute"
	}
	if w.toolCalls >= b.limits.ToolCallsPerHour {
		return false, "budget_exceeded: tool_calls_per_hour"
	}
	if isSuggestion && w.suggestions >= b.limits.SuggestionsPerHour {
		return false, "budget_exceeded: suggestions_per_hour"
	}
	w.requests++
	w.toolCalls++
	if isSuggestion {
		w.suggestions++
	}
	return true, ""
}
