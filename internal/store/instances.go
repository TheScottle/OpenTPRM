package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
	"github.com/google/uuid"
)

// QuestionnaireInstance is a pinned template version assigned to an engagement.
type QuestionnaireInstance struct {
	ID                string `json:"id"`
	TemplateVersionID string `json:"template_version_id"`
	EngagementID      string `json:"engagement_id"`
	AssessmentID      string `json:"assessment_id,omitempty"`
	PinnedHash        string `json:"pinned_hash"`
	Status            string `json:"status"`
	DeltaOf           string `json:"delta_of,omitempty"`
	CreatedBy         string `json:"created_by"`
	UpdatedBy         string `json:"updated_by"`
	CreatedAt         string `json:"created_at,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	RowVersion        int64  `json:"row_version,omitempty"`
}

// ResponseRevision is an immutable answers snapshot for an instance.
type ResponseRevision struct {
	ID         string `json:"id"`
	InstanceID string `json:"instance_id"`
	Revision   int    `json:"revision"`
	AnswersJSON string `json:"answers_json"`
	Actor      string `json:"actor"`
	TS         string `json:"ts"`
}

// AnswerReview is per-question review/scoring (QST review).
type AnswerReview struct {
	ID          string  `json:"id"`
	InstanceID  string  `json:"instance_id"`
	QuestionKey string  `json:"question_key"`
	Status      string  `json:"status"`
	Score       float64 `json:"score"`
	Reviewer    string  `json:"reviewer"`
	Notes       string  `json:"notes,omitempty"`
	UpdatedAt   string  `json:"updated_at,omitempty"`
}

// CreateQuestionnaireInstance pins a published template version to an engagement.
// When DeltaOf is set, prior answers are used for AT-15 prefill metadata (returned separately).
func (s *Store) CreateQuestionnaireInstance(ctx context.Context, in QuestionnaireInstance) (QuestionnaireInstance, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return QuestionnaireInstance{}, err
	}
	if in.TemplateVersionID == "" || in.EngagementID == "" {
		return QuestionnaireInstance{}, fmt.Errorf("template_version_id and engagement_id required")
	}
	ver, err := s.GetTemplateVersion(ctx, in.TemplateVersionID)
	if err != nil {
		return QuestionnaireInstance{}, err
	}
	if ver.Status != "published" {
		return QuestionnaireInstance{}, fmt.Errorf("template version must be published")
	}
	if in.PinnedHash == "" {
		in.PinnedHash = ver.ContentHash
	}
	if in.PinnedHash != ver.ContentHash {
		return QuestionnaireInstance{}, fmt.Errorf("pinned_hash mismatch")
	}
	if in.Status == "" {
		in.Status = "draft"
	}
	if in.ID == "" {
		in.ID = uuid.Must(uuid.NewV7()).String()
	}
	now := nowUTC()
	in.CreatedAt, in.UpdatedAt = now, now
	_, err = s.db.ExecContext(ctx, `INSERT INTO questionnaire_instances(
		id, template_version_id, engagement_id, assessment_id, pinned_hash, status, delta_of,
		created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		in.ID, in.TemplateVersionID, in.EngagementID, in.AssessmentID, in.PinnedHash, in.Status, in.DeltaOf,
		now, in.CreatedBy, now, in.UpdatedBy)
	return in, err
}

// GetQuestionnaireInstance loads one instance.
func (s *Store) GetQuestionnaireInstance(ctx context.Context, id string) (QuestionnaireInstance, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return QuestionnaireInstance{}, err
	}
	var in QuestionnaireInstance
	err := s.db.QueryRowContext(ctx, `SELECT id, template_version_id, engagement_id, assessment_id, pinned_hash, status, delta_of,
		created_by, updated_by, created_at, updated_at, row_version
		FROM questionnaire_instances WHERE id=?`, id).
		Scan(&in.ID, &in.TemplateVersionID, &in.EngagementID, &in.AssessmentID, &in.PinnedHash, &in.Status, &in.DeltaOf,
			&in.CreatedBy, &in.UpdatedBy, &in.CreatedAt, &in.UpdatedAt, &in.RowVersion)
	return in, err
}

// ListQuestionnaireInstances lists instances, optionally filtered by engagement_id.
func (s *Store) ListQuestionnaireInstances(ctx context.Context, engagementID string) ([]QuestionnaireInstance, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	var (
		rows *sql.Rows
		err  error
	)
	if engagementID == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, template_version_id, engagement_id, assessment_id, pinned_hash, status, delta_of,
			created_by, updated_by, created_at, updated_at, row_version FROM questionnaire_instances ORDER BY created_at`)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, template_version_id, engagement_id, assessment_id, pinned_hash, status, delta_of,
			created_by, updated_by, created_at, updated_at, row_version FROM questionnaire_instances WHERE engagement_id=? ORDER BY created_at`, engagementID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuestionnaireInstance
	for rows.Next() {
		var in QuestionnaireInstance
		if err := rows.Scan(&in.ID, &in.TemplateVersionID, &in.EngagementID, &in.AssessmentID, &in.PinnedHash, &in.Status, &in.DeltaOf,
			&in.CreatedBy, &in.UpdatedBy, &in.CreatedAt, &in.UpdatedAt, &in.RowVersion); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// ListQuestionnaireInstancesByVendor lists instances for engagements belonging to vendorID (third_party_id).
func (s *Store) ListQuestionnaireInstancesByVendor(ctx context.Context, vendorID string) ([]QuestionnaireInstance, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	if vendorID == "" {
		return nil, fmt.Errorf("vendor_id required")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT qi.id, qi.template_version_id, qi.engagement_id, qi.assessment_id, qi.pinned_hash, qi.status, qi.delta_of,
		qi.created_by, qi.updated_by, qi.created_at, qi.updated_at, qi.row_version
		FROM questionnaire_instances qi
		INNER JOIN engagements e ON e.id = qi.engagement_id
		WHERE e.third_party_id=?
		ORDER BY qi.created_at`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuestionnaireInstance
	for rows.Next() {
		var in QuestionnaireInstance
		if err := rows.Scan(&in.ID, &in.TemplateVersionID, &in.EngagementID, &in.AssessmentID, &in.PinnedHash, &in.Status, &in.DeltaOf,
			&in.CreatedBy, &in.UpdatedBy, &in.CreatedAt, &in.UpdatedAt, &in.RowVersion); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// LatestAnswers returns the newest response revision answers map for an instance.
func (s *Store) LatestAnswers(ctx context.Context, instanceID string) (map[string]any, int, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, 0, err
	}
	var rev int
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT revision, answers_json FROM response_revisions WHERE instance_id=? ORDER BY revision DESC LIMIT 1`, instanceID).
		Scan(&rev, &raw)
	if err == sql.ErrNoRows {
		return map[string]any{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	var answers map[string]any
	if err := json.Unmarshal([]byte(raw), &answers); err != nil {
		return nil, 0, err
	}
	if answers == nil {
		answers = map[string]any{}
	}
	return answers, rev, nil
}

// AppendResponseRevision stores a new answers revision (immutable history).
func (s *Store) AppendResponseRevision(ctx context.Context, instanceID, actor, answersJSON string) (ResponseRevision, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ResponseRevision{}, err
	}
	if !json.Valid([]byte(answersJSON)) {
		return ResponseRevision{}, fmt.Errorf("answers_json must be valid JSON")
	}
	_, err := s.GetQuestionnaireInstance(ctx, instanceID)
	if err != nil {
		return ResponseRevision{}, err
	}
	var maxRev sql.NullInt64
	_ = s.db.QueryRowContext(ctx, `SELECT MAX(revision) FROM response_revisions WHERE instance_id=?`, instanceID).Scan(&maxRev)
	next := 1
	if maxRev.Valid {
		next = int(maxRev.Int64) + 1
	}
	now := nowUTC()
	rr := ResponseRevision{
		ID: uuid.Must(uuid.NewV7()).String(), InstanceID: instanceID, Revision: next,
		AnswersJSON: answersJSON, Actor: actor, TS: now,
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO response_revisions(id, instance_id, revision, answers_json, actor, ts) VALUES(?,?,?,?,?,?)`,
		rr.ID, rr.InstanceID, rr.Revision, rr.AnswersJSON, rr.Actor, rr.TS)
	if err != nil {
		return ResponseRevision{}, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE questionnaire_instances SET status=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
		"in_progress", now, actor, instanceID)
	return rr, nil
}

// ListResponseRevisions lists revisions for an instance.
func (s *Store) ListResponseRevisions(ctx context.Context, instanceID string) ([]ResponseRevision, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, instance_id, revision, answers_json, actor, ts FROM response_revisions WHERE instance_id=? ORDER BY revision`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResponseRevision
	for rows.Next() {
		var rr ResponseRevision
		if err := rows.Scan(&rr.ID, &rr.InstanceID, &rr.Revision, &rr.AnswersJSON, &rr.Actor, &rr.TS); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, rows.Err()
}

// UpsertAnswerReview creates or updates a per-question review.
func (s *Store) UpsertAnswerReview(ctx context.Context, rev AnswerReview) (AnswerReview, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return AnswerReview{}, err
	}
	if rev.InstanceID == "" || rev.QuestionKey == "" {
		return AnswerReview{}, fmt.Errorf("instance_id and question_key required")
	}
	if rev.Status == "" {
		rev.Status = "pending"
	}
	now := nowUTC()
	rev.UpdatedAt = now
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM answer_reviews WHERE instance_id=? AND question_key=?`, rev.InstanceID, rev.QuestionKey).Scan(&existing)
	if err == sql.ErrNoRows {
		rev.ID = uuid.Must(uuid.NewV7()).String()
		_, err = s.db.ExecContext(ctx, `INSERT INTO answer_reviews(id, instance_id, question_key, status, score, reviewer, notes, updated_at)
			VALUES(?,?,?,?,?,?,?,?)`, rev.ID, rev.InstanceID, rev.QuestionKey, rev.Status, rev.Score, rev.Reviewer, rev.Notes, now)
		return rev, err
	}
	if err != nil {
		return AnswerReview{}, err
	}
	rev.ID = existing
	_, err = s.db.ExecContext(ctx, `UPDATE answer_reviews SET status=?, score=?, reviewer=?, notes=?, updated_at=? WHERE id=?`,
		rev.Status, rev.Score, rev.Reviewer, rev.Notes, now, rev.ID)
	return rev, err
}

// ListAnswerReviews lists reviews for an instance.
func (s *Store) ListAnswerReviews(ctx context.Context, instanceID string) ([]AnswerReview, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, instance_id, question_key, status, score, reviewer, notes, updated_at FROM answer_reviews WHERE instance_id=? ORDER BY question_key`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnswerReview
	for rows.Next() {
		var r AnswerReview
		if err := rows.Scan(&r.ID, &r.InstanceID, &r.QuestionKey, &r.Status, &r.Score, &r.Reviewer, &r.Notes, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// InstanceScore aggregates review scores for an instance.
func (s *Store) InstanceScore(ctx context.Context, instanceID string) (float64, int, error) {
	reviews, err := s.ListAnswerReviews(ctx, instanceID)
	if err != nil {
		return 0, 0, err
	}
	var sum float64
	for _, r := range reviews {
		sum += r.Score
	}
	return sum, len(reviews), nil
}

// DeltaPrefillForInstance builds AT-15 prefill from a prior instance and optional current answers.
func (s *Store) DeltaPrefillForInstance(ctx context.Context, priorInstanceID string, current map[string]any) (questionnaire.DeltaPrefill, error) {
	prior, _, err := s.LatestAnswers(ctx, priorInstanceID)
	if err != nil {
		return questionnaire.DeltaPrefill{}, err
	}
	if current == nil {
		current = map[string]any{}
		for k, v := range prior {
			current[k] = v
		}
	}
	return questionnaire.BuildDeltaPrefill(prior, current), nil
}
