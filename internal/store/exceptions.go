package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/domain/exception"
	"github.com/google/uuid"
)

var (
	ErrSOD2RequesterApprover = errors.New("SOD-2: requester cannot approve their own exception")
	ErrExceptionNotPending   = errors.New("exception is not pending approval")
)

// ExceptionRecord is an exceptions row (EXC-001).
type ExceptionRecord struct {
	ID                string `json:"id"`
	EngagementID      string `json:"engagement_id"`
	Scope             string `json:"scope"`
	Rationale         string `json:"rationale"`
	Requester         string `json:"requester"`
	Status            string `json:"status"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	DecisionPayload   string `json:"decision_payload,omitempty"`
	DecisionSignature string `json:"decision_signature,omitempty"`
	ApprovedBy        string `json:"approved_by,omitempty"`
	ApprovedAt        string `json:"approved_at,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
	CreatedBy         string `json:"created_by"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	UpdatedBy         string `json:"updated_by"`
	RowVersion        int64  `json:"row_version,omitempty"`
	Classification    string `json:"classification,omitempty"`
	Restricted        bool   `json:"restricted,omitempty"`
}

// CreateException inserts a pending exception (EXC-001).
func (s *Store) CreateException(ctx context.Context, e ExceptionRecord) (ExceptionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ExceptionRecord{}, err
	}
	if e.EngagementID == "" || e.Requester == "" {
		return ExceptionRecord{}, fmt.Errorf("engagement_id and requester required")
	}
	if e.ID == "" {
		e.ID = uuid.Must(uuid.NewV7()).String()
	}
	if e.Status == "" {
		e.Status = "pending"
	}
	if e.Classification == "" {
		e.Classification = "Internal"
	}
	if e.CreatedBy == "" {
		e.CreatedBy = e.Requester
	}
	if e.UpdatedBy == "" {
		e.UpdatedBy = e.Requester
	}
	if e.ExpiresAt == "" {
		e.ExpiresAt = time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO exceptions(
		id, engagement_id, scope, rationale, requester, status, expires_at,
		decision_payload, decision_signature, approved_by, approved_at,
		created_at, created_by, updated_at, updated_by, classification, restricted)
		VALUES(?,?,?,?,?,?,?,?,NULL,'','',?,?,?,?,?,?)`,
		e.ID, e.EngagementID, e.Scope, e.Rationale, e.Requester, e.Status, e.ExpiresAt,
		"", now, e.CreatedBy, now, e.UpdatedBy, e.Classification, boolToInt(e.Restricted))
	if err != nil {
		return ExceptionRecord{}, err
	}
	e.CreatedAt, e.UpdatedAt = now, now
	return e, nil
}

// GetException loads one exception.
func (s *Store) GetException(ctx context.Context, id string) (ExceptionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ExceptionRecord{}, err
	}
	var e ExceptionRecord
	var sig []byte
	var restricted int
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, scope, rationale, requester, status, expires_at,
		decision_payload, decision_signature, approved_by, approved_at,
		created_at, created_by, updated_at, updated_by, row_version, classification, restricted
		FROM exceptions WHERE id=?`, id).Scan(
		&e.ID, &e.EngagementID, &e.Scope, &e.Rationale, &e.Requester, &e.Status, &e.ExpiresAt,
		&e.DecisionPayload, &sig, &e.ApprovedBy, &e.ApprovedAt,
		&e.CreatedAt, &e.CreatedBy, &e.UpdatedAt, &e.UpdatedBy, &e.RowVersion, &e.Classification, &restricted)
	if errors.Is(err, sql.ErrNoRows) {
		return ExceptionRecord{}, fmt.Errorf("exception not found")
	}
	if err != nil {
		return ExceptionRecord{}, err
	}
	if len(sig) > 0 {
		e.DecisionSignature = hex.EncodeToString(sig)
	}
	e.Restricted = restricted == 1
	return e, nil
}

// ListExceptions returns exceptions, optionally filtered by engagement.
func (s *Store) ListExceptions(ctx context.Context, engagementID string) ([]ExceptionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	q := `SELECT id, engagement_id, scope, rationale, requester, status, expires_at,
		decision_payload, approved_by, approved_at, created_at, created_by, updated_at, updated_by,
		row_version, classification FROM exceptions`
	var rows *sql.Rows
	var err error
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx, q+` WHERE engagement_id=? ORDER BY created_at DESC`, engagementID)
	} else {
		rows, err = s.db.QueryContext(ctx, q+` ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExceptionRecord
	for rows.Next() {
		var e ExceptionRecord
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.Scope, &e.Rationale, &e.Requester, &e.Status, &e.ExpiresAt,
			&e.DecisionPayload, &e.ApprovedBy, &e.ApprovedAt, &e.CreatedAt, &e.CreatedBy, &e.UpdatedAt, &e.UpdatedBy,
			&e.RowVersion, &e.Classification); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ApproveException enforces SOD-2, persists a signed decision, and marks approved (EXC-002/ASM-006).
func (s *Store) ApproveException(ctx context.Context, id, approverID string, payload exception.Payload, signatureHex string) (ExceptionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ExceptionRecord{}, err
	}
	e, err := s.GetException(ctx, id)
	if err != nil {
		return ExceptionRecord{}, err
	}
	if e.Status != "pending" {
		return ExceptionRecord{}, ErrExceptionNotPending
	}
	if e.Requester != "" && e.Requester == approverID {
		return ExceptionRecord{}, ErrSOD2RequesterApprover
	}
	payload.ExceptionID = id
	payload.ApproverID = approverID
	if payload.DecidedAt.IsZero() {
		payload.DecidedAt = time.Now().UTC()
	}
	if payload.AssessmentID == "" {
		payload.AssessmentID = e.EngagementID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ExceptionRecord{}, err
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return ExceptionRecord{}, fmt.Errorf("invalid signature hex: %w", err)
	}
	now := nowUTC()
	res, err := s.db.ExecContext(ctx, `UPDATE exceptions SET status='approved', decision_payload=?, decision_signature=?,
		approved_by=?, approved_at=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=? AND status='pending'`,
		string(body), sig, approverID, now, now, approverID, id)
	if err != nil {
		return ExceptionRecord{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ExceptionRecord{}, ErrExceptionNotPending
	}
	return s.GetException(ctx, id)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
