package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/TheScottle/OpenTPRM/internal/authz"
)

// APIRouter holds versioned REST handlers. Expanded across M1–M8.
type APIRouter struct {
	App *App
}

func (a *App) routeAPI(w http.ResponseWriter, r *http.Request) {
	ac := a.authContext(r)
	ctx := authz.WithContext(r.Context(), ac)
	r = r.WithContext(ctx)

	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/me" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"id": ac.PrincipalID, "roles": ac.Roles, "type": ac.PrincipalType,
		})
	case path == "/vendors" || strings.HasPrefix(path, "/vendors/"):
		a.handleVendors(w, r, ac)
	case path == "/intakes" || strings.HasPrefix(path, "/intakes/"):
		a.handleIntakes(w, r, ac)
	case path == "/assessments" || strings.HasPrefix(path, "/assessments/"):
		a.handleAssessments(w, r, ac)
	case path == "/questionnaire-templates" || strings.HasPrefix(path, "/questionnaire-templates"):
		a.handleQuestionnaires(w, r, ac)
	case path == "/questionnaire-instances" || strings.HasPrefix(path, "/questionnaire-instances"):
		a.handleQuestionnaireInstances(w, r, ac)
	case path == "/uploads" || strings.HasPrefix(path, "/uploads"):
		a.handleUploads(w, r, ac)
	case path == "/evidence" || strings.HasPrefix(path, "/evidence"):
		a.handleEvidence(w, r, ac)
	case path == "/findings" || strings.HasPrefix(path, "/findings"):
		a.handleFindings(w, r, ac)
	case strings.HasPrefix(path, "/risk"):
		a.handleRisk(w, r, ac)
	case path == "/exceptions" || strings.HasPrefix(path, "/exceptions"):
		a.handleExceptions(w, r, ac)
	case path == "/contracts" || strings.HasPrefix(path, "/contracts"):
		a.handleContracts(w, r, ac)
	case path == "/monitoring/signals" || strings.HasPrefix(path, "/monitoring"):
		a.handleMonitoring(w, r, ac)
	case path == "/suggestions" || strings.HasPrefix(path, "/suggestions"):
		a.handleSuggestions(w, r, ac)
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
	// Development bootstrap: X-OpenTPRM-User / X-OpenTPRM-Roles headers when no session.
	// Production uses cookie sessions / DPoP (wired in authn package).
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
	return authz.Context{
		PrincipalID:   uid,
		PrincipalType: pt,
		Roles:         roles,
		DelegatorID:   r.Header.Get("X-OpenTPRM-Delegator"),
		ClientID:      r.Header.Get("X-OpenTPRM-Client"),
		Scopes:        strings.Split(strings.TrimSpace(r.Header.Get("X-OpenTPRM-Scopes")), " "),
		AAL:           2,
		IP:            r.RemoteAddr,
		TraceID:       r.Header.Get("X-Request-Id"),
	}
}

func (a *App) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPIDocument)
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
