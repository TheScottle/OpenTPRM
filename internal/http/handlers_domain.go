package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/domain/assessment"
	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
	"github.com/TheScottle/OpenTPRM/internal/domain/exception"
	"github.com/TheScottle/OpenTPRM/internal/domain/intake"
	"github.com/TheScottle/OpenTPRM/internal/domain/risk"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func (a *App) handleIntakes(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if strings.HasSuffix(r.URL.Path, ":submit") && r.Method == http.MethodPost {
		id := extractID(r.URL.Path, "/api/v1/intakes/", ":submit")
		if !a.authorize(w, ac, authz.ActionIntakeSubmit, authz.Resource{Type: "intake", ID: id}) {
			return
		}
		in, err := a.Store.GetIntake(r.Context(), id)
		if err != nil {
			writeProblem(w, 404, "not_found", "intake not found")
			return
		}
		var factors intake.Factors
		_ = json.Unmarshal([]byte(in.FactorScoresJSON), &factors)
		if factors.DataSensitivity == 0 {
			// Derive from answers if factors not pre-set
			var answers map[string]any
			_ = json.Unmarshal([]byte(in.AnswersJSON), &answers)
			factors = intake.FactorsFromAnswers(answers)
		}
		result := intake.ComputeTier(factors)
		plan := intake.DiligencePlan(result.Tier, factors)
		in.WeightedScore = result.Score
		in.Tier = result.Tier
		in.PlanJSON = mustJSON(plan)
		in.FactorScoresJSON = mustJSON(factors)
		in.Status = "submitted"
		if err := a.Store.UpdateIntake(r.Context(), in); err != nil {
			writeProblem(w, 500, "error", "update failed")
			return
		}
		writeJSON(w, 200, map[string]any{"intake": in, "tier": result.Tier, "score": result.Score, "plan": plan, "floors": result.FloorsApplied})
		return
	}
	if r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "intake", ID: "*"}) {
			return
		}
		var in store.Intake
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		in.ID = uuid.Must(uuid.NewV7()).String()
		in.CreatedBy = ac.PrincipalID
		in.UpdatedBy = ac.PrincipalID
		in.Status = "draft"
		if err := a.Store.CreateIntake(r.Context(), in); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, in)
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleAssessments(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if strings.Contains(r.URL.Path, ":transition") && r.Method == http.MethodPost {
		id := extractID(r.URL.Path, "/api/v1/assessments/", ":transition")
		if !a.authorize(w, ac, authz.ActionAssessmentTransition, authz.Resource{Type: "assessment", ID: id}) {
			return
		}
		var body struct {
			To     string `json:"to"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		as, err := a.Store.GetAssessment(r.Context(), id)
		if err != nil {
			writeProblem(w, 404, "not_found", "not found")
			return
		}
		if err := assessment.CanTransition(assessment.State(as.State), assessment.State(body.To)); err != nil {
			writeProblem(w, 422, "illegal_transition", err.Error())
			return
		}
		from := as.State
		as.State = body.To
		as.UpdatedBy = ac.PrincipalID
		if err := a.Store.TransitionAssessment(r.Context(), as, from, ac.PrincipalID, body.Reason); err != nil {
			writeProblem(w, 500, "error", "transition failed")
			return
		}
		writeJSON(w, 200, as)
		return
	}
	if r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionAssessmentTransition, authz.Resource{Type: "assessment", ID: "*"}) {
			return
		}
		var as store.Assessment
		if err := json.NewDecoder(r.Body).Decode(&as); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		as.ID = uuid.Must(uuid.NewV7()).String()
		as.State = string(assessment.Draft)
		as.CreatedBy = ac.PrincipalID
		as.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateAssessment(r.Context(), as); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, as)
		return
	}
	if r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionAssessmentRead, authz.Resource{Type: "assessment", ID: "*"}) {
			return
		}
		items, err := a.Store.ListAssessments(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleQuestionnaires(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")

	// POST /questionnaire-templates/{id}/versions/{vid}:publish
	if strings.Contains(path, ":publish") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire", ID: "*"}) {
			return
		}
		// path like /questionnaire-templates/{tid}/versions/{vid}:publish
		rest := strings.TrimPrefix(path, "/questionnaire-templates/")
		parts := strings.Split(rest, "/")
		if len(parts) < 3 {
			writeProblem(w, 400, "bad_request", "version id required")
			return
		}
		vid := strings.TrimSuffix(parts[2], ":publish")
		got, err := a.Store.PublishTemplateVersion(r.Context(), vid, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "publish_failed", err.Error())
			return
		}
		w.Header().Set("ETag", etagVersion(got.RowVersion))
		writeJSON(w, 200, got)
		return
	}

	// POST /questionnaire-templates/{id}/versions
	if strings.Contains(path, "/versions") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire", ID: "*"}) {
			return
		}
		tid := extractID(r.URL.Path, "/api/v1/questionnaire-templates/", "/versions")
		var body store.TemplateVersionRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.TemplateID = tid
		body.LastEditor = ac.PrincipalID
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		body.Status = "draft"
		if err := a.Store.CreateTemplateVersion(r.Context(), body); err != nil {
			writeProblem(w, 400, "bad_request", err.Error())
			return
		}
		writeJSON(w, 201, body)
		return
	}

	if strings.Contains(path, "/versions") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire", ID: "*"}) {
			return
		}
		tid := extractID(r.URL.Path, "/api/v1/questionnaire-templates/", "/versions")
		items, err := a.Store.ListTemplateVersions(r.Context(), tid)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire", ID: "*"}) {
			return
		}
		items, err := a.Store.ListTemplates(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire", ID: "*"}) {
			return
		}
		var body store.TemplateRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateTemplate(r.Context(), body); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleCustomFields(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasPrefix(path, "/custom-field-defs") {
		switch r.Method {
		case http.MethodGet:
			if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "custom_field", ID: "*"}) {
				return
			}
			ot := r.URL.Query().Get("object_type")
			if ot == "" {
				ot = "third_party"
			}
			items, err := a.Store.ListCustomFieldDefs(r.Context(), ot)
			if err != nil {
				writeProblem(w, 500, "error", "list failed")
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
		case http.MethodPost:
			if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "custom_field", ID: "*"}) {
				return
			}
			var body store.CustomFieldDef
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			body.ID = uuid.Must(uuid.NewV7()).String()
			body.CreatedBy = ac.PrincipalID
			if err := a.Store.CreateCustomFieldDef(r.Context(), body); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
			writeJSON(w, 201, body)
		default:
			writeProblem(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}
	// /custom-fields values
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "custom_field", ID: "*"}) {
			return
		}
		ot := r.URL.Query().Get("object_type")
		oid := r.URL.Query().Get("object_id")
		items, err := a.Store.ListCustomFieldValues(r.Context(), ot, oid)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPut, http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "custom_field", ID: "*"}) {
			return
		}
		var body store.CustomFieldValue
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.SetCustomFieldValue(r.Context(), body); err != nil {
			writeProblem(w, 400, "bad_request", err.Error())
			return
		}
		writeJSON(w, 200, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleQuestionnaireInstances(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleUploads(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")

	// POST /uploads/{id}:complete
	if strings.Contains(path, ":complete") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "evidence", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/uploads/", ":complete")
		ev, err := a.Store.CompleteUpload(r.Context(), id, a.Blobs, ac.PrincipalID)
		if err != nil {
			writeJSON(w, 422, map[string]any{"status": "rejected", "reason": err.Error()})
			return
		}
		writeJSON(w, 202, ev)
		return
	}

	// PUT /uploads/{id} — append chunk
	if strings.HasPrefix(path, "/uploads/") && r.Method == http.MethodPut {
		if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "evidence", ID: "*"}) {
			return
		}
		id := strings.TrimPrefix(path, "/uploads/")
		id = strings.Trim(id, "/")
		r.Body = http.MaxBytesReader(w, r.Body, evidence.MaxUploadBytes)
		u, err := a.Store.AppendUploadChunk(r.Context(), id, r.Body, evidence.MaxUploadBytes)
		if err != nil {
			writeProblem(w, 422, "upload_failed", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"id": u.ID, "size_bytes": u.SizeBytes, "status": u.Status})
		return
	}

	if r.Method != http.MethodPost {
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "evidence", ID: "*"}) {
		return
	}

	ct := r.Header.Get("Content-Type")
	// JSON session create for chunked uploads.
	if strings.HasPrefix(ct, "application/json") {
		var body struct {
			EngagementID string `json:"engagement_id"`
			DeclaredName string `json:"declared_name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		u, err := a.Store.CreateUploadSession(r.Context(), store.UploadSession{
			EngagementID: body.EngagementID,
			DeclaredName: body.DeclaredName,
			Uploader:     ac.PrincipalID,
		})
		if err != nil {
			writeProblem(w, 500, "error", err.Error())
			return
		}
		writeJSON(w, 201, u)
		return
	}

	// Single-shot raw body: create session, write chunk, complete (AT-08 edge).
	r.Body = http.MaxBytesReader(w, r.Body, evidence.MaxUploadBytes)
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, 413, "too_large", "upload exceeds limits")
		return
	}
	if _, err := evidence.ValidateUpload(buf); err != nil {
		writeJSON(w, 422, map[string]any{"status": "rejected_malformed", "reason": err.Error()})
		return
	}
	engID := r.URL.Query().Get("engagement_id")
	u, err := a.Store.CreateUploadSession(r.Context(), store.UploadSession{
		EngagementID: engID,
		DeclaredName: r.URL.Query().Get("name"),
		Uploader:     ac.PrincipalID,
	})
	if err != nil {
		writeProblem(w, 500, "error", err.Error())
		return
	}
	if _, err := a.Store.AppendUploadChunk(r.Context(), u.ID, bytes.NewReader(buf), evidence.MaxUploadBytes); err != nil {
		writeProblem(w, 422, "upload_failed", err.Error())
		return
	}
	if engID == "" {
		// Without engagement, validate-only path (legacy 202 shape).
		magic, _ := evidence.DetectType(buf)
		writeJSON(w, 202, map[string]any{"id": u.ID, "status": "quarantined", "magic": magic})
		return
	}
	ev, err := a.Store.CompleteUpload(r.Context(), u.ID, a.Blobs, ac.PrincipalID)
	if err != nil {
		writeJSON(w, 422, map[string]any{"status": "rejected", "reason": err.Error()})
		return
	}
	writeJSON(w, 202, ev)
}

func (a *App) handleEvidence(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionEvidenceReadContent, authz.Resource{Type: "evidence", ID: "*"}) {
		return
	}
	items, err := a.Store.ListEvidence(r.Context())
	if err != nil {
		writeProblem(w, 500, "error", "list failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (a *App) handleFindings(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	action := authz.ActionFindingRead
	if r.Method != http.MethodGet {
		action = authz.ActionFindingWrite
	}
	if !a.authorize(w, ac, action, authz.Resource{Type: "finding", ID: "*"}) {
		return
	}
	if r.Method == http.MethodGet {
		items, err := a.Store.ListFindings(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleRisk(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionAssessmentRead, authz.Resource{Type: "risk", ID: "*"}) {
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/compute") {
		var in risk.Input
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		writeJSON(w, 200, risk.Compute(in))
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleExceptions(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if strings.Contains(r.URL.Path, ":approve") {
		// Agents must never approve
		if ac.PrincipalType == authz.PrincipalAgent {
			writeProblem(w, 403, "forbidden", "agents cannot approve")
			return
		}
		if !a.authorize(w, ac, authz.ActionExceptionApprove, authz.Resource{Type: "exception", ID: "*"}) {
			return
		}
		var payload exception.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		payload.ApproverID = ac.PrincipalID
		payload.DecidedAt = time.Now().UTC()
		body, err := payload.CanonicalJSON()
		if err != nil {
			writeProblem(w, 500, "error", "canonical failed")
			return
		}
		sig, err := a.Keyring.SignEd25519(body)
		if err != nil {
			writeProblem(w, 500, "error", "sign failed")
			return
		}
		writeJSON(w, 200, map[string]any{"payload": payload, "signature": sig})
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleContracts(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "contract", ID: "*"}) {
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleMonitoring(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "monitoring", ID: "*"}) {
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleSuggestions(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleChangeRequests(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleAgentClients(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.HasRole("security_administrator") {
		writeProblem(w, 403, "forbidden", "security_administrator required")
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleModels(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.HasRole("security_administrator") {
		writeProblem(w, 403, "forbidden", "security_administrator required")
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}})
}

func (a *App) handleAgentREST(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	writeProblem(w, 501, "not_implemented", "use /mcp via Agent Gateway")
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionAdminAny, authz.Resource{Type: "admin", ID: "*"}) {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func extractID(path, prefix, suffix string) string {
	s := strings.TrimPrefix(path, prefix)
	s = strings.TrimSuffix(s, suffix)
	s = strings.Trim(s, "/")
	return s
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
