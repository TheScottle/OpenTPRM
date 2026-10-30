package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/domain/reporting"
	"github.com/google/uuid"
)

// ExportRecord is an exports row (RPT-004).
type ExportRecord struct {
	ID              string `json:"id"`
	Format          string `json:"format"`
	Scope           string `json:"scope"`
	Classification  string `json:"classification"`
	Marking         string `json:"marking"`
	Status          string `json:"status"`
	Requester       string `json:"requester"`
	SecondApprover  string `json:"second_approver,omitempty"`
	StepUpRequired  bool   `json:"step_up_required"`
	PayloadRef      string `json:"payload_ref,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
	CreatedBy       string `json:"created_by"`
}

// CreateExport queues an export with GEN-012 markings applied to metadata.
func (s *Store) CreateExport(ctx context.Context, e ExportRecord, markings map[string]string) (ExportRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ExportRecord{}, err
	}
	if e.Requester == "" {
		return ExportRecord{}, fmt.Errorf("requester required")
	}
	if e.ID == "" {
		e.ID = uuid.Must(uuid.NewV7()).String()
	}
	if e.Format == "" {
		e.Format = "json"
	}
	if e.Classification == "" {
		e.Classification = "Internal"
	}
	if e.Status == "" {
		e.Status = "pending"
	}
	if e.CreatedBy == "" {
		e.CreatedBy = e.Requester
	}
	e.Marking = reporting.ResolveMarking(e.Classification, markings)
	e.StepUpRequired = reporting.SensitiveClassification(e.Classification)
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO exports(
		id, format, scope, classification, marking, status, requester, second_approver,
		step_up_required, payload_ref, created_at, updated_at, created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.Format, e.Scope, e.Classification, e.Marking, e.Status, e.Requester, e.SecondApprover,
		boolToInt(e.StepUpRequired), e.PayloadRef, now, now, e.CreatedBy)
	if err != nil {
		return ExportRecord{}, err
	}
	e.CreatedAt, e.UpdatedAt = now, now
	return e, nil
}

// ListExports returns export jobs newest first.
func (s *Store) ListExports(ctx context.Context) ([]ExportRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, format, scope, classification, marking, status, requester,
		second_approver, step_up_required, payload_ref, created_at, updated_at, created_by
		FROM exports ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExportRecord
	for rows.Next() {
		var e ExportRecord
		var step int
		if err := rows.Scan(&e.ID, &e.Format, &e.Scope, &e.Classification, &e.Marking, &e.Status, &e.Requester,
			&e.SecondApprover, &step, &e.PayloadRef, &e.CreatedAt, &e.UpdatedAt, &e.CreatedBy); err != nil {
			return nil, err
		}
		e.StepUpRequired = step == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetExport loads one export.
func (s *Store) GetExport(ctx context.Context, id string) (ExportRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ExportRecord{}, err
	}
	var e ExportRecord
	var step int
	err := s.db.QueryRowContext(ctx, `SELECT id, format, scope, classification, marking, status, requester,
		second_approver, step_up_required, payload_ref, created_at, updated_at, created_by
		FROM exports WHERE id=?`, id).Scan(
		&e.ID, &e.Format, &e.Scope, &e.Classification, &e.Marking, &e.Status, &e.Requester,
		&e.SecondApprover, &step, &e.PayloadRef, &e.CreatedAt, &e.UpdatedAt, &e.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return ExportRecord{}, fmt.Errorf("export not found")
	}
	if err != nil {
		return ExportRecord{}, err
	}
	e.StepUpRequired = step == 1
	return e, nil
}
