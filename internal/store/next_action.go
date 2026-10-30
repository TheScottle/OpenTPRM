package store

import (
	"context"
	"database/sql"
	"time"
)

// NextActionHints are candidate due dates feeding INV-009.
type NextActionHints struct {
	RenewalDate      string
	ReassessmentDue  string
	ExpiringEvidence []string
	OverdueRemediation []string
}

// EarliestDue returns the earliest non-empty RFC3339 / date string among candidates.
func EarliestDue(candidates ...string) string {
	var best time.Time
	var bestRaw string
	for _, c := range candidates {
		if c == "" {
			continue
		}
		t, ok := parseFlexibleDate(c)
		if !ok {
			continue
		}
		if bestRaw == "" || t.Before(best) {
			best = t
			bestRaw = c
		}
	}
	return bestRaw
}

func parseFlexibleDate(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano, time.RFC3339, "2006-01-02", "2006-01-02T15:04:05Z07:00",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// CollectNextActionHints gathers renewal, reassessment, expiring evidence, and overdue remediation (INV-009).
func (s *Store) CollectNextActionHints(ctx context.Context, engagementID string) (NextActionHints, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return NextActionHints{}, err
	}
	var h NextActionHints
	_ = s.db.QueryRowContext(ctx, `SELECT renewal_date, COALESCE(reassessment_due,'') FROM engagements WHERE id=?`, engagementID).
		Scan(&h.RenewalDate, &h.ReassessmentDue)

	rows, err := s.db.QueryContext(ctx, `SELECT freshness_expires FROM evidence
		WHERE engagement_id=? AND freshness_expires!='' AND status NOT IN ('rejected_malformed','shredded')`, engagementID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err == nil && d != "" {
				h.ExpiringEvidence = append(h.ExpiringEvidence, d)
			}
		}
	}

	rows2, err := s.db.QueryContext(ctx, `SELECT COALESCE(r.due_date, f.due_date) FROM findings f
		LEFT JOIN remediation_plans r ON r.finding_id=f.id
		WHERE f.engagement_id=? AND f.status IN ('open','remediating')
		  AND (COALESCE(r.due_date, f.due_date) != '')`, engagementID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var d string
			if err := rows2.Scan(&d); err == nil && d != "" {
				h.OverdueRemediation = append(h.OverdueRemediation, d)
			}
		}
	}
	return h, nil
}

// RecalculateNextActionDue sets next_action_due from the earliest INV-009 hint.
func (s *Store) RecalculateNextActionDue(ctx context.Context, engagementID string) (string, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return "", err
	}
	h, err := s.CollectNextActionHints(ctx, engagementID)
	if err != nil {
		return "", err
	}
	cands := []string{h.RenewalDate, h.ReassessmentDue}
	cands = append(cands, h.ExpiringEvidence...)
	cands = append(cands, h.OverdueRemediation...)
	due := EarliestDue(cands...)
	return due, s.ComputeNextActionDue(ctx, engagementID, due)
}

// SetEngagementReassessmentDue updates the reassessment hint used by INV-009.
func (s *Store) SetEngagementReassessmentDue(ctx context.Context, engagementID, due string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE engagements SET reassessment_due=?, updated_at=?, row_version=row_version+1 WHERE id=?`,
		due, nowUTC(), engagementID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// InsertEvidenceExpiring is a test/helper insert for INV-009 freshness hints.
func (s *Store) InsertEvidenceExpiring(ctx context.Context, id, engagementID, freshnessExpires, actor string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO evidence(
		id, engagement_id, status, evidence_type, freshness_expires, created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?)`,
		id, engagementID, "accepted", "soc2", freshnessExpires, now, actor, now, actor)
	return err
}

// InsertFindingDue is a test/helper insert for INV-009 remediation hints.
func (s *Store) InsertFindingDue(ctx context.Context, id, engagementID, due, actor string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO findings(
		id, engagement_id, title, severity, status, finding_type, due_date, created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		id, engagementID, "gap", "high", "open", "control_gap", due, now, actor, now, actor)
	return err
}
