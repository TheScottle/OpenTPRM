package httpserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/ai"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/domain/assessment"
	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
	"github.com/TheScottle/OpenTPRM/internal/domain/exception"
	"github.com/TheScottle/OpenTPRM/internal/domain/intake"
	"github.com/TheScottle/OpenTPRM/internal/domain/reporting"
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
	if r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "intake", ID: "*"}) {
			return
		}
		items, err := a.Store.ListIntakes(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
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
			switch {
			case errors.Is(err, store.ErrEngagementRequired), errors.Is(err, store.ErrEngagementNotFound):
				writeProblem(w, 400, "bad_request", err.Error())
			default:
				writeProblem(w, 500, "error", "create failed")
			}
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
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")

	// POST /questionnaire-instances/{id}/responses
	if strings.Contains(path, "/responses") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", "/responses")
		var body struct {
			AnswersJSON string         `json:"answers_json"`
			Answers     map[string]any `json:"answers"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		raw := body.AnswersJSON
		if raw == "" && body.Answers != nil {
			b, _ := json.Marshal(body.Answers)
			raw = string(b)
		}
		if raw == "" {
			raw = "{}"
		}
		rr, err := a.Store.AppendResponseRevision(r.Context(), id, ac.PrincipalID, raw)
		if err != nil {
			writeProblem(w, 422, "response_failed", err.Error())
			return
		}
		writeJSON(w, 201, rr)
		return
	}

	// GET /questionnaire-instances/{id}/responses
	if strings.Contains(path, "/responses") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", "/responses")
		items, err := a.Store.ListResponseRevisions(r.Context(), id)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}

	// POST /questionnaire-instances/{id}/reviews
	if strings.Contains(path, "/reviews") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", "/reviews")
		var body store.AnswerReview
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.InstanceID = id
		body.Reviewer = ac.PrincipalID
		got, err := a.Store.UpsertAnswerReview(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "review_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}

	// GET /questionnaire-instances/{id}/reviews or /score
	if strings.HasSuffix(path, "/score") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", "/score")
		sum, n, err := a.Store.InstanceScore(r.Context(), id)
		if err != nil {
			writeProblem(w, 500, "error", "score failed")
			return
		}
		writeJSON(w, 200, map[string]any{"instance_id": id, "score_sum": sum, "reviewed": n})
		return
	}

	if strings.Contains(path, "/reviews") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", "/reviews")
		items, err := a.Store.ListAnswerReviews(r.Context(), id)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}

	// GET /questionnaire-instances/{id}:delta — AT-15 prefill
	if strings.Contains(path, ":delta") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/questionnaire-instances/", ":delta")
		inst, err := a.Store.GetQuestionnaireInstance(r.Context(), id)
		if err != nil {
			writeProblem(w, 404, "not_found", "instance not found")
			return
		}
		priorID := inst.DeltaOf
		if priorID == "" {
			priorID = id
		}
		current, _, _ := a.Store.LatestAnswers(r.Context(), id)
		delta, err := a.Store.DeltaPrefillForInstance(r.Context(), priorID, current)
		if err != nil {
			writeProblem(w, 500, "error", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"instance": inst, "delta": delta})
		return
	}

	// GET /questionnaire-instances/{id}
	if strings.HasPrefix(path, "/questionnaire-instances/") && r.Method == http.MethodGet &&
		!strings.Contains(path, "/") {
		// fall through — single segment handled below
	}
	if rest := strings.TrimPrefix(path, "/questionnaire-instances/"); rest != "" && rest != path && r.Method == http.MethodGet {
		if !strings.Contains(rest, "/") && !strings.Contains(rest, ":") {
			if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: rest}) {
				return
			}
			inst, err := a.Store.GetQuestionnaireInstance(r.Context(), rest)
			if err != nil {
				writeProblem(w, 404, "not_found", "instance not found")
				return
			}
			writeJSON(w, 200, inst)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		items, err := a.Store.ListQuestionnaireInstances(r.Context(), r.URL.Query().Get("engagement_id"))
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "questionnaire_instance", ID: "*"}) {
			return
		}
		var body store.QuestionnaireInstance
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateQuestionnaireInstance(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		out := map[string]any{"instance": got}
		if got.DeltaOf != "" {
			delta, err := a.Store.DeltaPrefillForInstance(r.Context(), got.DeltaOf, nil)
			if err == nil {
				out["delta"] = delta
			}
		}
		writeJSON(w, 201, out)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
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
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")

	// PUT /evidence/{id}/pages — store sanitized viewer text
	if strings.Contains(path, "/pages") && r.Method == http.MethodPut {
		if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "evidence", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/evidence/", "/pages")
		var body store.EvidencePage
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.EvidenceID = id
		got, err := a.Store.PutEvidencePage(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "page_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}

	// GET /evidence/{id}/pages/{n}/text — safe viewer JSON stub
	// GET /evidence/{id}/pages/{n}/html — CSP-safe HTML viewer (EVD-007)
	if strings.Contains(path, "/pages/") && r.Method == http.MethodGet &&
		(strings.HasSuffix(path, "/text") || strings.HasSuffix(path, "/html")) {
		if !a.authorize(w, ac, authz.ActionEvidenceReadContent, authz.Resource{Type: "evidence", ID: "*"}) {
			return
		}
		rest := strings.TrimPrefix(path, "/evidence/")
		parts := strings.Split(rest, "/")
		if len(parts) < 4 {
			writeProblem(w, 400, "bad_request", "page number required")
			return
		}
		pageNum, err := strconv.Atoi(parts[2])
		if err != nil || pageNum < 1 {
			writeProblem(w, 400, "bad_request", "invalid page")
			return
		}
		p, err := a.Store.GetEvidencePage(r.Context(), parts[0], pageNum)
		if err != nil {
			writeProblem(w, 404, "not_found", "page not found")
			return
		}
		stub := evidence.ViewerPageStub{
			EvidenceID: p.EvidenceID, PageNum: p.PageNum, Text: p.TextContent, TextSHA256: p.TextSHA256, Safe: true,
		}
		if strings.HasSuffix(path, "/html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(evidence.RenderViewerHTML(stub)))
			return
		}
		writeJSON(w, 200, stub)
		return
	}

	if strings.Contains(path, "/pages") && r.Method == http.MethodGet {
		if !a.authorize(w, ac, authz.ActionEvidenceReadContent, authz.Resource{Type: "evidence", ID: "*"}) {
			return
		}
		id := extractID(r.URL.Path, "/api/v1/evidence/", "/pages")
		items, err := a.Store.ListEvidencePages(r.Context(), id)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}

	// PUT/GET /evidence/{id}/soc-review
	if strings.Contains(path, "/soc-review") {
		id := extractID(r.URL.Path, "/api/v1/evidence/", "/soc-review")
		switch r.Method {
		case http.MethodGet:
			if !a.authorize(w, ac, authz.ActionEvidenceReadContent, authz.Resource{Type: "evidence", ID: id}) {
				return
			}
			rev, err := a.Store.GetSOCReview(r.Context(), id)
			if err != nil {
				writeProblem(w, 404, "not_found", "soc review not found")
				return
			}
			writeJSON(w, 200, rev)
		case http.MethodPut, http.MethodPost:
			if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "evidence", ID: id}) {
				return
			}
			var body store.SOCReview
			if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			body.EvidenceID = id
			body.UpdatedBy = ac.PrincipalID
			got, err := a.Store.UpsertSOCReview(r.Context(), body)
			if err != nil {
				writeProblem(w, 422, "soc_review_failed", err.Error())
				return
			}
			writeJSON(w, 200, got)
		default:
			writeProblem(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}

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
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.Contains(path, ":transition") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionFindingWrite, authz.Resource{Type: "finding", ID: "*"}) {
			return
		}
		id := extractID(path, "/findings/", ":transition")
		var body struct {
			Status            string `json:"status"`
			ClosureEvidenceID string `json:"closure_evidence_id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.TransitionFinding(r.Context(), id, body.Status, ac.PrincipalID, body.ClosureEvidenceID)
		if err != nil {
			writeProblem(w, 422, "transition_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	if strings.HasSuffix(path, "/remediation-plan") {
		fid := strings.TrimSuffix(strings.TrimPrefix(path, "/findings/"), "/remediation-plan")
		fid = strings.Trim(fid, "/")
		switch r.Method {
		case http.MethodGet:
			if !a.authorize(w, ac, authz.ActionFindingRead, authz.Resource{Type: "finding", ID: fid}) {
				return
			}
			got, err := a.Store.GetRemediationPlan(r.Context(), fid)
			if err != nil {
				writeProblem(w, 404, "not_found", "remediation plan not found")
				return
			}
			writeJSON(w, 200, got)
		case http.MethodPut, http.MethodPost:
			if !a.authorize(w, ac, authz.ActionFindingWrite, authz.Resource{Type: "finding", ID: fid}) {
				return
			}
			var body store.RemediationPlan
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			body.FindingID = fid
			got, err := a.Store.UpsertRemediationPlan(r.Context(), body)
			if err != nil {
				writeProblem(w, 422, "remediation_failed", err.Error())
				return
			}
			writeJSON(w, 200, got)
		default:
			writeProblem(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}
	action := authz.ActionFindingRead
	if r.Method != http.MethodGet {
		action = authz.ActionFindingWrite
	}
	if !a.authorize(w, ac, action, authz.Resource{Type: "finding", ID: "*"}) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := a.Store.ListFindings(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		var body store.Finding
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.CreateFinding(r.Context(), body, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleRisk(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "/risk-register" || strings.HasPrefix(path, "/risk-register") {
		if !a.authorize(w, ac, authz.ActionAssessmentRead, authz.Resource{Type: "risk", ID: "*"}) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			items, err := a.Store.ListRiskResults(r.Context(), r.URL.Query().Get("engagement_id"))
			if err != nil {
				writeProblem(w, 500, "error", "list failed")
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
		case http.MethodPost:
			var body struct {
				EngagementID string     `json:"engagement_id"`
				AssessmentID string     `json:"assessment_id"`
				Input        risk.Input `json:"input"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			got, err := a.Store.PersistRiskResult(r.Context(), body.EngagementID, body.AssessmentID, ac.PrincipalID, body.Input)
			if err != nil {
				writeProblem(w, 422, "persist_failed", err.Error())
				return
			}
			writeJSON(w, 201, got)
		default:
			writeProblem(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}
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
	items, err := a.Store.ListRiskResults(r.Context(), "")
	if err != nil {
		writeProblem(w, 500, "error", "list failed")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (a *App) handleExceptions(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.Contains(path, ":approve") && r.Method == http.MethodPost {
		// Agents must never approve (SOD-4 / AT-03).
		if ac.PrincipalType == authz.PrincipalAgent {
			writeProblem(w, 403, "forbidden", "agents cannot approve")
			return
		}
		if !a.authorize(w, ac, authz.ActionExceptionApprove, authz.Resource{Type: "exception", ID: "*"}) {
			return
		}
		id := extractID(path, "/exceptions/", ":approve")
		var payload exception.Payload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		payload.ExceptionID = id
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
		sigHex := hex.EncodeToString(sig)
		got, err := a.Store.ApproveException(r.Context(), id, ac.PrincipalID, payload, sigHex)
		if err != nil {
			if errors.Is(err, store.ErrSOD2RequesterApprover) {
				writeProblem(w, 403, "sod2", err.Error())
				return
			}
			writeProblem(w, 422, "approve_failed", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"exception": got, "payload": payload, "signature": sigHex})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionFindingRead, authz.Resource{Type: "exception", ID: "*"}) {
			return
		}
		eng := r.URL.Query().Get("engagement_id")
		items, err := a.Store.ListExceptions(r.Context(), eng)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionFindingWrite, authz.Resource{Type: "exception", ID: "*"}) {
			return
		}
		var body store.ExceptionRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.Requester = ac.PrincipalID
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateException(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleReports(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "report", ID: "*"}) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	typ := strings.TrimPrefix(path, "/reports/")
	typ = strings.Trim(typ, "/")
	if typ == "" || !reporting.ReportTypes[typ] {
		writeProblem(w, 404, "not_found", "unknown report type")
		return
	}
	classification := r.URL.Query().Get("classification")
	if classification == "" {
		classification = "Internal"
	}
	var body string
	switch typ {
	case "exceptions":
		items, err := a.Store.ListExceptions(r.Context(), "")
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		raw, _ := json.Marshal(map[string]any{"items": items, "type": typ})
		body = string(raw)
	case "inventory":
		items, err := a.Store.ListVendors(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		raw, _ := json.Marshal(map[string]any{"items": items, "type": typ})
		body = string(raw)
	case "committee":
		// Committee pack (RPT-002): marked text ZIP (pdfcpu PDF deferred — ADR-0004).
		format := r.URL.Query().Get("format")
		summary := "Committee pack.\nSecond approver required for Client-Confidential bulk exports via /exports/{id}:approve.\n"
		if format == "zip" || format == "bundle" || r.Header.Get("Accept") == "application/zip" {
			zipBytes, marking, err := reporting.BuildCommitteePack(classification, a.Cfg.Labels.Markings, summary)
			if err != nil {
				writeProblem(w, 500, "error", "committee pack failed")
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="committee-pack.zip"`)
			w.Header().Set("X-OpenTPRM-Classification", classification)
			w.Header().Set("X-OpenTPRM-Marking", marking)
			w.WriteHeader(200)
			_, _ = w.Write(zipBytes)
			return
		}
		raw, _ := json.Marshal(map[string]any{
			"type": "committee", "format": "marked_zip",
			"note": "text ZIP pack available via ?format=zip; second approver required for Client-Confidential bulk exports",
			"classification": classification,
			"download": "/api/v1/reports/committee?format=zip&classification=" + classification,
		})
		body = string(raw)
	default:
		body = `{"type":"` + typ + `","status":"stub"}`
	}
	doc := reporting.ApplyMarking(classification, a.Cfg.Labels.Markings, body)
	writeJSON(w, 200, doc)
}

func (a *App) handleExports(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasSuffix(path, ":bundle") && r.Method == http.MethodGet {
		id := extractID(r.URL.Path, "/api/v1/exports/", ":bundle")
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "export", ID: id}) {
			return
		}
		exp, err := a.Store.GetExport(r.Context(), id)
		if err != nil {
			writeProblem(w, 404, "not_found", "export not found")
			return
		}
		content := fmt.Sprintf("export_id=%s\nformat=%s\nscope=%s\nstatus=%s\nrequester=%s\nsecond_approver=%s\n",
			exp.ID, exp.Format, exp.Scope, exp.Status, exp.Requester, exp.SecondApprover)
		zipBytes, marking, err := reporting.BuildMarkedZip(exp.Classification, a.Cfg.Labels.Markings, []reporting.PackFile{
			{Name: "export/metadata.txt", Content: content},
		})
		if err != nil {
			writeProblem(w, 500, "error", "bundle failed")
			return
		}
		_ = marking
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="export-`+id+`.zip"`)
		w.WriteHeader(200)
		_, _ = w.Write(zipBytes)
		return
	}
	if strings.Contains(path, ":approve") && r.Method == http.MethodPost {
		id := extractID(r.URL.Path, "/api/v1/exports/", ":approve")
		if !a.authorize(w, ac, authz.ActionExportBulk, authz.Resource{Type: "export", ID: id}) {
			return
		}
		if !ac.StepUpFresh() {
			writeProblem(w, 401, "step_up_required", "second approval of sensitive export requires step-up")
			return
		}
		got, err := a.Store.ApproveExportSecond(r.Context(), id, ac.PrincipalID)
		if err != nil {
			if errors.Is(err, store.ErrExportSODSecondApprover) {
				writeProblem(w, 403, "sod", err.Error())
				return
			}
			writeProblem(w, 422, "approve_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "export", ID: "*"}) {
			return
		}
		items, err := a.Store.ListExports(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		var body store.ExportRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		if body.Classification == "" {
			body.Classification = "Internal"
		}
		action := authz.ActionVendorRead
		if reporting.SensitiveClassification(body.Classification) {
			action = authz.ActionExportBulk
			// Require recent step-up for Privileged / Client-Confidential bulk (RPT-004).
			if !ac.StepUpFresh() {
				writeProblem(w, 401, "step_up_required", "bulk export of sensitive data requires WebAuthn step-up")
				return
			}
		}
		if !a.authorize(w, ac, action, authz.Resource{Type: "export", ID: "*", Classification: body.Classification}) {
			return
		}
		body.Requester = ac.PrincipalID
		body.CreatedBy = ac.PrincipalID
		got, err := a.Store.CreateExport(r.Context(), body, a.Cfg.Labels.Markings)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleAnswerLibrary(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "answer_library", ID: "*"}) {
			return
		}
		vendorID := r.URL.Query().Get("vendor_id")
		if vendorID == "" {
			writeProblem(w, 400, "bad_request", "vendor_id required")
			return
		}
		items, err := a.Store.ListAnswerLibrary(r.Context(), vendorID)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "answer_library", ID: "*"}) {
			return
		}
		var body store.AnswerLibraryEntry
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.UpsertAnswerLibrary(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "upsert_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleContracts(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "contract", ID: "*"}) {
			return
		}
		items, err := a.Store.ListContracts(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "contract", ID: "*"}) {
			return
		}
		var body store.ContractRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateContract(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleMonitoring(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.Contains(path, ":disposition") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "monitoring", ID: "*"}) {
			return
		}
		id := extractID(path, "/monitoring/signals/", ":disposition")
		var body struct {
			Disposition string `json:"disposition"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.SetMonitoringDisposition(r.Context(), id, body.Disposition, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "disposition_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "monitoring", ID: "*"}) {
			return
		}
		items, err := a.Store.ListMonitoringSignals(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "monitoring", ID: "*"}) {
			return
		}
		var body store.MonitoringSignal
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateMonitoringSignal(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleObligations(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "obligation", ID: "*"}) {
			return
		}
		items, err := a.Store.ListObligations(r.Context(), r.URL.Query().Get("engagement_id"))
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "obligation", ID: "*"}) {
			return
		}
		var body store.Obligation
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateObligation(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleClients(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasSuffix(path, "/requirements:flow-down") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "client", ID: "*"}) {
			return
		}
		// /clients/{id}/requirements/{rid}:flow-down
		rest := strings.TrimPrefix(path, "/clients/")
		parts := strings.Split(rest, "/")
		if len(parts) < 3 {
			writeProblem(w, 400, "bad_request", "client and requirement id required")
			return
		}
		reqID := strings.TrimSuffix(parts[2], ":flow-down")
		var body struct {
			EngagementID string `json:"engagement_id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.FlowDownRequirement(r.Context(), reqID, body.EngagementID, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "flow_down_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
		return
	}
	if strings.HasSuffix(path, "/requirements") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "client", ID: "*"}) {
			return
		}
		cid := strings.TrimSuffix(strings.TrimPrefix(path, "/clients/"), "/requirements")
		cid = strings.Trim(cid, "/")
		var body store.ClientRequirement
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ClientID = cid
		body.CreatedBy = ac.PrincipalID
		got, err := a.Store.CreateClientRequirement(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
		return
	}
	if r.Method == http.MethodPost && path == "/clients" {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "client", ID: "*"}) {
			return
		}
		var body store.ClientRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		got, err := a.Store.CreateClient(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleOffboarding(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasSuffix(path, "/items") && (r.Method == http.MethodPost || r.Method == http.MethodPatch) {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "offboarding", ID: "*"}) {
			return
		}
		eid := strings.TrimSuffix(strings.TrimPrefix(path, "/offboarding/"), "/items")
		eid = strings.Trim(eid, "/")
		var body struct {
			ItemID      string `json:"item_id"`
			Done        bool   `json:"done"`
			EvidenceRef string `json:"evidence_ref"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.MarkOffboardingItem(r.Context(), eid, body.ItemID, ac.PrincipalID, body.Done, body.EvidenceRef)
		if err != nil {
			writeProblem(w, 422, "update_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "offboarding", ID: "*"}) {
			return
		}
		eid := strings.TrimPrefix(path, "/offboarding/")
		got, err := a.Store.GetOffboardingChecklist(r.Context(), eid)
		if err != nil {
			writeProblem(w, 404, "not_found", "checklist not found")
			return
		}
		writeJSON(w, 200, got)
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "offboarding", ID: "*"}) {
			return
		}
		var body struct {
			EngagementID string `json:"engagement_id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.CreateOffboardingChecklist(r.Context(), body.EngagementID, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleLegalHolds(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.Contains(path, ":release") && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionAdminAny, authz.Resource{Type: "legal_hold", ID: "*"}) {
			return
		}
		id := extractID(path, "/legal-holds/", ":release")
		if err := a.Store.ReleaseLegalHold(r.Context(), id, ac.PrincipalID); err != nil {
			writeProblem(w, 422, "release_failed", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": id})
		return
	}
	if r.Method != http.MethodPost {
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	if !a.authorize(w, ac, authz.ActionAdminAny, authz.Resource{Type: "legal_hold", ID: "*"}) {
		return
	}
	var body struct {
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	got, err := a.Store.PlaceLegalHold(r.Context(), body.ObjectType, body.ObjectID, body.Reason, ac.PrincipalID)
	if err != nil {
		writeProblem(w, 422, "create_failed", err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{
		"hold": got, "backup_retention_notice": store.BackupRetentionNotice(store.DefaultRetention()),
	})
}

func (a *App) handleSuggestions(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasSuffix(path, ":accept") && r.Method == http.MethodPost {
		id := extractID(r.URL.Path, "/api/v1/suggestions/", ":accept")
		if !a.authorize(w, ac, authz.ActionChangeRequestApprove, authz.Resource{Type: "suggestion", ID: id}) {
			return
		}
		var body struct {
			SourceText string `json:"source_text"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		got, err := a.Store.AcceptSuggestion(r.Context(), id, body.SourceText, ac.PrincipalID)
		if err != nil {
			status := 422
			if errors.Is(err, ai.ErrUnverifiedCitation) || errors.Is(err, ai.ErrMissingSourceText) {
				status = 409
			}
			writeProblem(w, status, "accept_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "suggestion", ID: "*"}) {
			return
		}
		items, err := a.Store.ListSuggestions(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionSuggest, authz.Resource{Type: "suggestion", ID: "*"}) {
			return
		}
		var body store.Suggestion
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.DelegatorID = ac.PrincipalID
		got, err := a.Store.CreateSuggestion(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleChangeRequests(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if strings.HasSuffix(path, ":approve") || strings.HasSuffix(path, ":reject") {
		decision := "approved"
		suffix := ":approve"
		if strings.HasSuffix(path, ":reject") {
			decision = "rejected"
			suffix = ":reject"
		}
		id := extractID(r.URL.Path, "/api/v1/change-requests/", suffix)
		if r.Method != http.MethodPost {
			writeProblem(w, 405, "method_not_allowed", "POST required")
			return
		}
		if !ac.StepUpFresh() {
			writeProblem(w, 401, "step_up_required", "change-request decision requires WebAuthn step-up")
			return
		}
		if !a.authorize(w, ac, authz.ActionChangeRequestApprove, authz.Resource{Type: "change_request", ID: id}) {
			return
		}
		var body struct {
			CurrentETag string `json:"current_etag"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		if body.CurrentETag == "" {
			body.CurrentETag = r.Header.Get("If-Match")
		}
		got, err := a.Store.DecideChangeRequest(r.Context(), id, decision, ac.PrincipalID, body.CurrentETag)
		if err != nil {
			status := 422
			if errors.Is(err, store.ErrStaleChangeRequest) {
				status = 409
			}
			writeProblem(w, status, "decide_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "change_request", ID: "*"}) {
			return
		}
		items, err := a.Store.ListChangeRequests(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionChangeRequest, authz.Resource{Type: "change_request", ID: "*"}) {
			return
		}
		var body store.ChangeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.DelegatorID = ac.PrincipalID
		got, err := a.Store.CreateChangeRequest(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleAgentClients(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.HasRole("security_administrator") {
		writeProblem(w, 403, "forbidden", "security_administrator required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := a.Store.ListAgentClients(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		var body store.AgentClient
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if body.OwnerUserID == "" {
			body.OwnerUserID = ac.PrincipalID
		}
		got, err := a.Store.CreateAgentClient(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleModels(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.HasRole("security_administrator") {
		writeProblem(w, 403, "forbidden", "security_administrator required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	isEndpoints := strings.HasPrefix(path, "/model-endpoints")
	if isEndpoints {
		rest := strings.TrimPrefix(path, "/model-endpoints")
		rest = strings.TrimPrefix(rest, "/")
		if rest != "" && !strings.Contains(rest, "/") {
			id := rest
			switch r.Method {
			case http.MethodGet:
				got, err := a.Store.GetModelEndpoint(r.Context(), id)
				if err != nil {
					writeProblem(w, 404, "not_found", "model endpoint not found")
					return
				}
				writeJSON(w, 200, got)
				return
			case http.MethodPatch, http.MethodPut:
				var body store.ModelEndpoint
				if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
					writeProblem(w, 400, "bad_request", "invalid json")
					return
				}
				body.ID = id
				got, err := a.Store.UpdateModelEndpoint(r.Context(), body)
				if err != nil {
					writeProblem(w, 422, "update_failed", err.Error())
					return
				}
				writeJSON(w, 200, got)
				return
			case http.MethodDelete:
				if err := a.Store.DeleteModelEndpoint(r.Context(), id); err != nil {
					writeProblem(w, 404, "not_found", err.Error())
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			default:
				writeProblem(w, 405, "method_not_allowed", "method not allowed")
				return
			}
		}
	}
	switch r.Method {
	case http.MethodGet:
		if isEndpoints {
			items, err := a.Store.ListModelEndpoints(r.Context())
			if err != nil {
				writeProblem(w, 500, "error", "list failed")
				return
			}
			writeJSON(w, 200, map[string]any{"items": items})
			return
		}
		items, err := a.Store.ListModels(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if isEndpoints {
			var body store.ModelEndpoint
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			body.CreatedBy = ac.PrincipalID
			got, err := a.Store.CreateModelEndpoint(r.Context(), body)
			if err != nil {
				writeProblem(w, 422, "create_failed", err.Error())
				return
			}
			writeJSON(w, 201, got)
			return
		}
		var body store.ModelRecord
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		got, err := a.Store.CreateModel(r.Context(), body)
		if err != nil {
			writeProblem(w, 422, "create_failed", err.Error())
			return
		}
		writeJSON(w, 201, got)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleAgentREST(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "/agent/tools" && r.Method == http.MethodGet {
		gw := a.ensureGateway()
		tools := gw.VisibleTools(ac)
		writeJSON(w, 200, map[string]any{"items": tools, "note": "invoke via POST /agent/call or /mcp"})
		return
	}
	if path == "/agent/call" && r.Method == http.MethodPost {
		var body struct {
			Tool      string          `json:"tool"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		name := body.Tool
		if name == "" {
			name = body.Name
		}
		if name == "" {
			writeProblem(w, 400, "bad_request", "tool name required")
			return
		}
		gw := a.ensureGateway()
		delegator := ac
		if ac.DelegatorID != "" {
			delegator.PrincipalID = ac.DelegatorID
			delegator.PrincipalType = authz.PrincipalWorkforce
		}
		res := gw.Call(r.Context(), ac, delegator, name, body.Arguments)
		if !res.OK {
			status := res.Status
			if status == 0 {
				status = 422
			}
			writeProblem(w, status, "agent_call_failed", res.Error)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "dry_run": res.DryRun, "result": json.RawMessage(res.Result)})
		return
	}
	writeProblem(w, 405, "method_not_allowed", "method not allowed")
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionAdminAny, authz.Resource{Type: "admin", ID: "*"}) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/admin/keys" || strings.HasPrefix(path, "/admin/keys"):
		writeJSON(w, 200, map[string]any{"items": []any{}, "note": "key actions dual-controlled; rotate API pending"})
	case path == "/admin/backups" || strings.HasPrefix(path, "/admin/backups"):
		writeJSON(w, 200, map[string]any{"items": []any{}, "note": "use opentprm backup|restore --verify-only (ARC-013)"})
	default:
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func (a *App) handleMeAgentGrants(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	ctx := authz.WithContext(r.Context(), ac)
	if strings.Contains(path, ":revoke") && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
		id := extractID(path, "/me/agent-grants/", ":revoke")
		if a.Store == nil {
			writeProblem(w, 503, "unavailable", "store unavailable")
			return
		}
		got, err := a.Store.RevokeAgentClientForOwner(ctx, id, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "revoke_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(path, "/me/agent-grants/") {
		id := strings.TrimPrefix(path, "/me/agent-grants/")
		id = strings.Trim(id, "/")
		if id == "" {
			writeProblem(w, 400, "bad_request", "grant id required")
			return
		}
		if a.Store == nil {
			writeProblem(w, 503, "unavailable", "store unavailable")
			return
		}
		got, err := a.Store.RevokeAgentClientForOwner(ctx, id, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 422, "revoke_failed", err.Error())
			return
		}
		writeJSON(w, 200, got)
		return
	}
	if r.Method != http.MethodGet {
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	items := []store.AgentClient{}
	if a.Store != nil && ac.Valid() {
		var err error
		items, err = a.Store.ListAgentClientsForOwner(ctx, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "principal_id": ac.PrincipalID})
}

func (a *App) handleTasks(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "task", ID: "*"}) {
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}, "note": "task queue stub (§10.2)"})
}

func (a *App) handleAuditEvents(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.HasRole("auditor") && !ac.HasRole("security_administrator") {
		writeProblem(w, http.StatusForbidden, "forbidden", "auditor or security_administrator required")
		return
	}
	writeJSON(w, 200, map[string]any{"items": []any{}, "note": "audit event list stub; use /audit:verify for chain check"})
}

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if ac.PrincipalID == "" || ac.PrincipalID == "anonymous" {
		writeProblem(w, 401, "unauthorized", "metrics require auth")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "note": "metrics stub"})
}

func (a *App) handleSOCReviewsAlias(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	// §10.2 /soc-reviews/{evidenceId} aliases evidence SOC review routes.
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/soc-reviews"), "/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		writeProblem(w, 404, "not_found", "evidence id required")
		return
	}
	id := rest
	if i := strings.IndexAny(id, "/:"); i >= 0 {
		id = id[:i]
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/api/v1/evidence/" + id + "/soc-review"
	if strings.Contains(rest, ":signoff") {
		r2.URL.Path = "/api/v1/evidence/" + id + "/soc-review:signoff"
	}
	a.handleEvidence(w, r2, ac)
}

type storeSuggestionWriter struct {
	app *App
	ac  authz.Context
}

func (w storeSuggestionWriter) CreateSuggestion(ctx context.Context, kind string, payload json.RawMessage, citations []ai.Citation, classification string) (ai.Suggestion, error) {
	cit, _ := json.Marshal(citations)
	got, err := w.app.Store.CreateSuggestion(ctx, store.Suggestion{
		Kind: kind, PayloadJSON: string(payload), CitationsJSON: string(cit),
		Classification: classification, DelegatorID: w.ac.PrincipalID, Status: "proposed",
	})
	if err != nil {
		return ai.Suggestion{}, err
	}
	return ai.Suggestion{
		ID: got.ID, Kind: got.Kind, Payload: json.RawMessage(got.PayloadJSON),
		Status: got.Status, Label: "AI suggestion — human review required",
	}, nil
}

func (w storeSuggestionWriter) WriteCallLog(ctx context.Context, endpointID, modelDigest, templateHash, inputHash, outputHash, principal string, tokens, latencyMs int) error {
	_, err := w.app.Store.InsertAICallLog(ctx, store.AICallLog{
		EndpointID: endpointID, ModelDigest: modelDigest, TemplateHash: templateHash,
		InputHash: inputHash, OutputHash: outputHash, Principal: principal,
		Tokens: tokens, LatencyMs: latencyMs,
	})
	return err
}

func (a *App) handleAIJobs(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if r.Method != http.MethodPost {
		writeProblem(w, 405, "method_not_allowed", "POST required")
		return
	}
	if !a.authorize(w, ac, authz.ActionSuggest, authz.Resource{Type: "suggestion", ID: "*"}) {
		return
	}
	var body ai.JobRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	if body.Principal == "" {
		body.Principal = ac.PrincipalID
	}
	writer := storeSuggestionWriter{app: a, ac: ac}
	res, err := ai.RunSuggestJobWithLog(r.Context(), a.Cfg.AIAssist.Enabled, writer, writer, body)
	if err != nil {
		status := 422
		if errors.Is(err, ai.ErrAssistDisabled) {
			status = 503
		} else if errors.Is(err, ai.ErrJobNotSuggestOnly) {
			status = 403
		}
		writeProblem(w, status, "ai_job_failed", err.Error())
		return
	}
	writeJSON(w, 201, res)
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
