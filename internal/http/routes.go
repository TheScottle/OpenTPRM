package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

// APIRouter holds versioned REST handlers. Expanded across M1–M8.
type APIRouter struct {
	App *App
}

func (a *App) routeAPI(w http.ResponseWriter, r *http.Request) {
	a.withIdempotency(w, r, a.routeAPIInner)
}

func (a *App) routeAPIInner(w http.ResponseWriter, r *http.Request) {
	ac := a.authContext(r)
	ctx := authz.WithContext(r.Context(), ac)
	r = r.WithContext(ctx)

	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/me" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"id": ac.PrincipalID, "roles": ac.Roles, "type": ac.PrincipalType,
		})
	case path == "/me/agent-grants" || strings.HasPrefix(path, "/me/agent-grants"):
		a.handleMeAgentGrants(w, r, ac)
	case strings.HasPrefix(path, "/auth/"):
		a.handleAuth(w, r, ac)
	case path == "/tasks" || strings.HasPrefix(path, "/tasks"):
		a.handleTasks(w, r, ac)
	case path == "/audit-events" || strings.HasPrefix(path, "/audit-events"):
		a.handleAuditEvents(w, r, ac)
	case path == "/metrics" && (r.Method == http.MethodGet):
		a.handleMetrics(w, r, ac)
	case path == "/soc-reviews" || strings.HasPrefix(path, "/soc-reviews/"):
		a.handleSOCReviewsAlias(w, r, ac)
	case path == "/vendors" || path == "/vendors:import" || strings.HasPrefix(path, "/vendors/"):
		a.handleVendors(w, r, ac)
	case path == "/fourth-party-links" || strings.HasPrefix(path, "/fourth-party-links"):
		a.handleFourthPartyLinks(w, r, ac)
	case path == "/custom-field-defs" || strings.HasPrefix(path, "/custom-field-defs") ||
		path == "/custom-fields" || strings.HasPrefix(path, "/custom-fields"):
		a.handleCustomFields(w, r, ac)
	case path == "/intakes" || strings.HasPrefix(path, "/intakes/"):
		a.handleIntakes(w, r, ac)
	case path == "/assessments" || strings.HasPrefix(path, "/assessments/"):
		a.handleAssessments(w, r, ac)
	case path == "/questionnaire-templates" || strings.HasPrefix(path, "/questionnaire-templates"):
		a.handleQuestionnaires(w, r, ac)
	case path == "/questionnaire-instances" || strings.HasPrefix(path, "/questionnaire-instances"):
		a.handleQuestionnaireInstances(w, r, ac)
	case path == "/answer-library" || strings.HasPrefix(path, "/answer-library"):
		a.handleAnswerLibrary(w, r, ac)
	case path == "/uploads" || strings.HasPrefix(path, "/uploads"):
		a.handleUploads(w, r, ac)
	case path == "/evidence" || strings.HasPrefix(path, "/evidence"):
		a.handleEvidence(w, r, ac)
	case path == "/findings" || strings.HasPrefix(path, "/findings"):
		a.handleFindings(w, r, ac)
	case path == "/risk-register" || strings.HasPrefix(path, "/risk"):
		a.handleRisk(w, r, ac)
	case path == "/exceptions" || strings.HasPrefix(path, "/exceptions"):
		a.handleExceptions(w, r, ac)
	case path == "/reports" || strings.HasPrefix(path, "/reports/"):
		a.handleReports(w, r, ac)
	case path == "/exports" || strings.HasPrefix(path, "/exports"):
		a.handleExports(w, r, ac)
	case path == "/contracts" || strings.HasPrefix(path, "/contracts"):
		a.handleContracts(w, r, ac)
	case path == "/obligations" || strings.HasPrefix(path, "/obligations"):
		a.handleObligations(w, r, ac)
	case path == "/clients" || strings.HasPrefix(path, "/clients"):
		a.handleClients(w, r, ac)
	case path == "/monitoring/signals" || strings.HasPrefix(path, "/monitoring"):
		a.handleMonitoring(w, r, ac)
	case path == "/offboarding" || strings.HasPrefix(path, "/offboarding"):
		a.handleOffboarding(w, r, ac)
	case path == "/legal-holds" || strings.HasPrefix(path, "/legal-holds"):
		a.handleLegalHolds(w, r, ac)
	case path == "/suggestions" || strings.HasPrefix(path, "/suggestions"):
		a.handleSuggestions(w, r, ac)
	case path == "/ai/jobs" || strings.HasPrefix(path, "/ai/jobs"):
		a.handleAIJobs(w, r, ac)
	case path == "/change-requests" || strings.HasPrefix(path, "/change-requests"):
		a.handleChangeRequests(w, r, ac)
	case path == "/agent-clients" || strings.HasPrefix(path, "/agent-clients"):
		a.handleAgentClients(w, r, ac)
	case path == "/model-endpoints" || strings.HasPrefix(path, "/model-endpoints") || path == "/models" || strings.HasPrefix(path, "/models"):
		a.handleModels(w, r, ac)
	case path == "/agent/tools" || path == "/agent/call":
		a.handleAgentREST(w, r, ac)
	case strings.HasPrefix(path, "/admin"):
		a.handleAdmin(w, r, ac)
	default:
		writeProblem(w, http.StatusNotFound, "not_found", "unknown API path")
	}
}

func (a *App) authContext(r *http.Request) authz.Context {
	traceID := r.Header.Get("X-Request-Id")

	// Prefer server-side session cookie (SEC-AN-004).
	if a.Sessions != nil {
		if c, err := r.Cookie(authn.SessionCookie); err == nil && c.Value != "" {
			if sess, err := a.Sessions.LookupByID(r.Context(), c.Value); err == nil {
				_ = a.Sessions.Touch(r.Context(), sess.IDHash)
				bg := false
				if a.BreakGlass != nil {
					bg = a.BreakGlass.Active(sess.UserID, sess.LastSeen)
				}
				return authz.Context{
					PrincipalID:   sess.UserID,
					PrincipalType: authz.PrincipalWorkforce,
					Roles:         sess.Roles,
					AAL:           sess.AAL,
					SessionID:     sess.IDHash,
					BreakGlass:    bg,
					StepUpAt:      sess.StepUpAt,
					IP:            r.RemoteAddr,
					TraceID:       traceID,
				}
			}
		}
	}

	// Development bootstrap headers — refused when AllowDevHeaders is false (production).
	if !a.AllowDevHeaders {
		return authz.Context{
			PrincipalID: "anonymous", PrincipalType: authz.PrincipalWorkforce,
			IP: r.RemoteAddr, TraceID: traceID,
		}
	}
	uid := r.Header.Get("X-OpenTPRM-User")
	if uid == "" {
		uid = "anonymous"
	}
	roles := strings.Split(r.Header.Get("X-OpenTPRM-Roles"), ",")
	if len(roles) == 1 && roles[0] == "" {
		roles = nil
	}
	pt := authz.PrincipalWorkforce
	if r.Header.Get("X-OpenTPRM-Principal") == "agent" {
		pt = authz.PrincipalAgent
	}
	ac := authz.Context{
		PrincipalID:   uid,
		PrincipalType: pt,
		Roles:         roles,
		DelegatorID:   r.Header.Get("X-OpenTPRM-Delegator"),
		ClientID:      r.Header.Get("X-OpenTPRM-Client"),
		Scopes:        strings.Split(strings.TrimSpace(r.Header.Get("X-OpenTPRM-Scopes")), " "),
		AAL:           2,
		IP:            r.RemoteAddr,
		TraceID:       traceID,
	}
	if r.Header.Get("X-OpenTPRM-StepUp") == "1" {
		ac.StepUpAt = time.Now().UTC()
	}
	return ac
}

func (a *App) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	ac, _ := authz.FromContext(r.Context())
	if !ac.HasRole("auditor") && !ac.HasRole("security_administrator") {
		writeProblem(w, http.StatusForbidden, "forbidden", "auditor or security_administrator required")
		return
	}
	if a.Audit == nil {
		writeProblem(w, http.StatusServiceUnavailable, "unavailable", "audit logger unavailable")
		return
	}
	res, err := a.Audit.Verify(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "error", "verify failed")
		return
	}
	status := http.StatusOK
	if !res.OK {
		status = http.StatusConflict
	}
	writeJSON(w, status, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) authorize(w http.ResponseWriter, ac authz.Context, action string, res authz.Resource) bool {
	if a.PDP == nil {
		return true
	}
	d := a.PDP.IsAuthorized(ac, action, res)
	if a.Audit != nil {
		_ = a.Audit.Append(rContext(ac), auditDecision(ac, action, res, d))
	}
	if !d.Allow {
		// SEC-AZ-005: 404 if not visible, 403 if visible but denied
		if res.Restricted && !contains(res.Allowlist, ac.PrincipalID) && !ac.BreakGlass {
			writeProblem(w, http.StatusNotFound, "not_found", "not found")
			return false
		}
		writeProblem(w, http.StatusForbidden, "forbidden", "authorization denied")
		return false
	}
	return true
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
