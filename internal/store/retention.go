package store

import (
	"context"
	"fmt"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/google/uuid"
)

// LegalHold is a legal_holds row (ARC-002).
type LegalHold struct {
	ID         string `json:"id"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	Reason     string `json:"reason"`
	CreatedAt  string `json:"created_at"`
	CreatedBy  string `json:"created_by"`
	ReleasedAt string `json:"released_at,omitempty"`
	ReleasedBy string `json:"released_by,omitempty"`
}

// RetentionPolicy mirrors config defaults (ARC-001).
type RetentionPolicy struct {
	AILogsDays            int `json:"ai_logs_days"`
	AuditYears            int `json:"audit_years"`
	EvidenceYearsAfterEnd int `json:"evidence_years_after_end"`
	SessionDays           int `json:"session_days"`
	BackupDaysShown       int `json:"backup_days_shown"`
}

// DefaultRetention returns ARC-001 defaults.
func DefaultRetention() RetentionPolicy {
	d := config.Default().Retention
	return RetentionPolicy{
		AILogsDays:            d.AILogsDays,
		AuditYears:            d.AuditYears,
		EvidenceYearsAfterEnd: d.EvidenceYearsAfterEnd,
		SessionDays:           30,
		BackupDaysShown:       30,
	}
}

// RetentionDeadline computes when a record type may be shredded after relationship end.
func RetentionDeadline(p RetentionPolicy, recordType string, relationshipEnd time.Time) time.Time {
	switch recordType {
	case "ai_log", "ai_prompt", "ai_output":
		return relationshipEnd.AddDate(0, 0, p.AILogsDays)
	case "session":
		return relationshipEnd.AddDate(0, 0, p.SessionDays)
	case "audit":
		return relationshipEnd.AddDate(p.AuditYears, 0, 0)
	default: // evidence, decisions, etc.
		return relationshipEnd.AddDate(p.EvidenceYearsAfterEnd, 0, 0)
	}
}

// BackupRetentionNotice returns ARC-004 text shown wherever deletion is offered.
func BackupRetentionNotice(p RetentionPolicy) string {
	return fmt.Sprintf("Shredded data may remain in backups for up to %d days until those backups expire.", p.BackupDaysShown)
}

// PlaceLegalHold inserts an active hold (ARC-002).
func (s *Store) PlaceLegalHold(ctx context.Context, objectType, objectID, reason, actor string) (LegalHold, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return LegalHold{}, err
	}
	if objectType == "" || objectID == "" || reason == "" {
		return LegalHold{}, fmt.Errorf("object_type, object_id, and reason required")
	}
	h := LegalHold{
		ID: uuid.Must(uuid.NewV7()).String(), ObjectType: objectType, ObjectID: objectID,
		Reason: reason, CreatedAt: nowUTC(), CreatedBy: actor,
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO legal_holds(id, object_type, object_id, reason, created_at, created_by) VALUES(?,?,?,?,?,?)`,
		h.ID, h.ObjectType, h.ObjectID, h.Reason, h.CreatedAt, h.CreatedBy)
	return h, err
}

// ReleaseLegalHold marks a hold released. ARC-002 dual-control is enforced when releaser != creator.
func (s *Store) ReleaseLegalHold(ctx context.Context, holdID, actor string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	var createdBy, releasedAt string
	err := s.db.QueryRowContext(ctx, `SELECT created_by, released_at FROM legal_holds WHERE id=?`, holdID).Scan(&createdBy, &releasedAt)
	if err != nil {
		return err
	}
	if releasedAt != "" {
		return fmt.Errorf("hold already released")
	}
	if createdBy == actor {
		return fmt.Errorf("ARC-002: second authorized user required to release legal hold")
	}
	_, err = s.db.ExecContext(ctx, `UPDATE legal_holds SET released_at=?, released_by=? WHERE id=?`, nowUTC(), actor, holdID)
	return err
}

// HasActiveLegalHold reports whether objectType/objectID has an unreleased hold.
func (s *Store) HasActiveLegalHold(ctx context.Context, objectType, objectID string) (bool, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM legal_holds WHERE object_type=? AND object_id=? AND released_at=''`,
		objectType, objectID).Scan(&n)
	return n > 0, err
}

// CanShredObject returns an error when an active legal hold blocks shredding (ARC-002).
func (s *Store) CanShredObject(ctx context.Context, objectType, objectID string) error {
	ok, err := s.HasActiveLegalHold(ctx, objectType, objectID)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("ARC-002: legal hold blocks shredding of %s/%s", objectType, objectID)
	}
	return nil
}
