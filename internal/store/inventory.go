package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateVendor inserts a third party.
func (s *Store) CreateVendor(ctx context.Context, v Vendor) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if v.Status == "" {
		v.Status = "prospect"
	}
	if v.Classification == "" {
		v.Classification = "Internal"
	}
	if v.AllowlistJSON == "" {
		v.AllowlistJSON = "[]"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO third_parties(
		id, legal_name, status, tier, created_at, created_by, updated_at, updated_by, classification, restricted, allowlist_json
	) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		v.ID, v.LegalName, v.Status, v.Tier, now, v.CreatedBy, now, v.UpdatedBy, v.Classification, boolInt(v.Restricted), v.AllowlistJSON)
	return err
}

// ListVendors returns vendors (visibility predicates applied by caller/Cedar).
func (s *Store) ListVendors(ctx context.Context) ([]Vendor, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, legal_name, status, tier, classification, restricted, allowlist_json, created_by, updated_by, created_at, updated_at FROM third_parties ORDER BY legal_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vendor
	for rows.Next() {
		var v Vendor
		var restricted int
		if err := rows.Scan(&v.ID, &v.LegalName, &v.Status, &v.Tier, &v.Classification, &restricted, &v.AllowlistJSON, &v.CreatedBy, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		v.Restricted = restricted == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

// CreateEngagement inserts an engagement (needed before intakes).
func (s *Store) CreateEngagement(ctx context.Context, id, thirdPartyID, owner string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO engagements(id, third_party_id, relationship_owner, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?)`, id, thirdPartyID, owner, now, owner, now, owner)
	return err
}

// CreateIntake inserts an intake row.
func (s *Store) CreateIntake(ctx context.Context, in Intake) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if in.AnswersJSON == "" {
		in.AnswersJSON = "{}"
	}
	if in.FactorScoresJSON == "" {
		in.FactorScoresJSON = "{}"
	}
	if in.PlanJSON == "" {
		in.PlanJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO intakes(
		id, engagement_id, answers_json, factor_scores_json, weighted_score, tier, plan_json, status,
		created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.ID, in.EngagementID, in.AnswersJSON, in.FactorScoresJSON, in.WeightedScore, in.Tier, in.PlanJSON, in.Status,
		now, in.CreatedBy, now, in.UpdatedBy)
	return err
}

func (s *Store) GetIntake(ctx context.Context, id string) (Intake, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Intake{}, err
	}
	var in Intake
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, answers_json, factor_scores_json, weighted_score, tier, plan_json, status, created_by, updated_by FROM intakes WHERE id=?`, id).
		Scan(&in.ID, &in.EngagementID, &in.AnswersJSON, &in.FactorScoresJSON, &in.WeightedScore, &in.Tier, &in.PlanJSON, &in.Status, &in.CreatedBy, &in.UpdatedBy)
	return in, err
}

func (s *Store) UpdateIntake(ctx context.Context, in Intake) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE intakes SET answers_json=?, factor_scores_json=?, weighted_score=?, tier=?, plan_json=?, status=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
		in.AnswersJSON, in.FactorScoresJSON, in.WeightedScore, in.Tier, in.PlanJSON, in.Status, now, in.UpdatedBy, in.ID)
	return err
}

func (s *Store) CreateAssessment(ctx context.Context, as Assessment) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if as.Type == "" {
		as.Type = "onboarding"
	}
	if as.PlanJSON == "" {
		as.PlanJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO assessments(id, engagement_id, type, state, plan_json, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?)`, as.ID, as.EngagementID, as.Type, as.State, as.PlanJSON, now, as.CreatedBy, now, as.UpdatedBy)
	return err
}

func (s *Store) GetAssessment(ctx context.Context, id string) (Assessment, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Assessment{}, err
	}
	var as Assessment
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, type, state, plan_json, created_by, updated_by FROM assessments WHERE id=?`, id).
		Scan(&as.ID, &as.EngagementID, &as.Type, &as.State, &as.PlanJSON, &as.CreatedBy, &as.UpdatedBy)
	return as, err
}

func (s *Store) ListAssessments(ctx context.Context) ([]Assessment, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, type, state, plan_json, created_by, updated_by FROM assessments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assessment
	for rows.Next() {
		var as Assessment
		if err := rows.Scan(&as.ID, &as.EngagementID, &as.Type, &as.State, &as.PlanJSON, &as.CreatedBy, &as.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, as)
	}
	return out, rows.Err()
}

func (s *Store) TransitionAssessment(ctx context.Context, as Assessment, from, actor, reason string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE assessments SET state=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
			as.State, now, as.UpdatedBy, as.ID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO assessment_transitions(id, assessment_id, from_state, to_state, actor, reason, ts) VALUES(?,?,?,?,?,?,?)`,
			uuid.Must(uuid.NewV7()).String(), as.ID, from, as.State, actor, reason, now)
		return err
	})
}

func (s *Store) ListTemplates(ctx context.Context) ([]Template, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind FROM questionnaire_templates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListEvidence(ctx context.Context) ([]Evidence, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, status, evidence_type, classification, license_tag FROM evidence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.Status, &e.EvidenceType, &e.Classification, &e.LicenseTag); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context) ([]Finding, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, title, severity, status, finding_type FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Title, &f.Severity, &f.Status, &f.FindingType); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ShredVendor destroys vendor data keys and leaves a tombstone (AT-14 / ARC-003).
func (s *Store) ShredVendor(ctx context.Context, vendorID, actor, policy string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM vendor_data_keys WHERE vendor_id=?`, vendorID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM evidence_pages WHERE evidence_id IN (SELECT id FROM evidence WHERE engagement_id IN (SELECT id FROM engagements WHERE third_party_id=?))`, vendorID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM evidence WHERE engagement_id IN (SELECT id FROM engagements WHERE third_party_id=?)`, vendorID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO tombstones(id, object_type, object_id, shredded_at, policy) VALUES(?,?,?,?,?)`,
			uuid.Must(uuid.NewV7()).String(), "third_party", vendorID, now, policy)
		return err
	})
}
