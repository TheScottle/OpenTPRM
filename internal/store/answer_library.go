package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// AnswerLibraryEntry is the latest accepted answer per vendor+question key (QST-035).
type AnswerLibraryEntry struct {
	ID               string `json:"id"`
	VendorID         string `json:"vendor_id"`
	QuestionKey      string `json:"question_key"`
	AnswerJSON       string `json:"answer_json"`
	EffectiveDate    string `json:"effective_date"`
	SourceInstanceID string `json:"source_instance_id,omitempty"`
	Status           string `json:"status"`
	UpdatedAt        string `json:"updated_at,omitempty"`
	UpdatedBy        string `json:"updated_by"`
}

// UpsertAnswerLibrary stores/replaces the latest accepted library answer for a key.
func (s *Store) UpsertAnswerLibrary(ctx context.Context, e AnswerLibraryEntry) (AnswerLibraryEntry, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return AnswerLibraryEntry{}, err
	}
	if e.VendorID == "" || e.QuestionKey == "" {
		return AnswerLibraryEntry{}, fmt.Errorf("vendor_id and question_key required")
	}
	if e.AnswerJSON == "" {
		e.AnswerJSON = "null"
	}
	if !json.Valid([]byte(e.AnswerJSON)) {
		return AnswerLibraryEntry{}, fmt.Errorf("answer_json must be valid JSON")
	}
	if e.Status == "" {
		e.Status = "accepted"
	}
	now := nowUTC()
	if e.EffectiveDate == "" {
		e.EffectiveDate = now[:10] // YYYY-MM-DD
	}
	e.UpdatedAt = now
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM answer_library WHERE vendor_id=? AND question_key=?`,
		e.VendorID, e.QuestionKey).Scan(&existing)
	if err == sql.ErrNoRows {
		e.ID = uuid.Must(uuid.NewV7()).String()
		_, err = s.db.ExecContext(ctx, `INSERT INTO answer_library(
			id, vendor_id, question_key, answer_json, effective_date, source_instance_id, status, updated_at, updated_by)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			e.ID, e.VendorID, e.QuestionKey, e.AnswerJSON, e.EffectiveDate, e.SourceInstanceID, e.Status, now, e.UpdatedBy)
		return e, err
	}
	if err != nil {
		return AnswerLibraryEntry{}, err
	}
	e.ID = existing
	_, err = s.db.ExecContext(ctx, `UPDATE answer_library SET answer_json=?, effective_date=?, source_instance_id=?, status=?, updated_at=?, updated_by=?
		WHERE id=?`, e.AnswerJSON, e.EffectiveDate, e.SourceInstanceID, e.Status, now, e.UpdatedBy, e.ID)
	return e, err
}

// ListAnswerLibrary returns library entries for a vendor (newest keys first by key).
func (s *Store) ListAnswerLibrary(ctx context.Context, vendorID string) ([]AnswerLibraryEntry, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, vendor_id, question_key, answer_json, effective_date, source_instance_id, status, updated_at, updated_by
		FROM answer_library WHERE vendor_id=? ORDER BY question_key`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnswerLibraryEntry
	for rows.Next() {
		var e AnswerLibraryEntry
		if err := rows.Scan(&e.ID, &e.VendorID, &e.QuestionKey, &e.AnswerJSON, &e.EffectiveDate, &e.SourceInstanceID, &e.Status, &e.UpdatedAt, &e.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetAnswerLibraryEntry loads one vendor+key entry.
func (s *Store) GetAnswerLibraryEntry(ctx context.Context, vendorID, questionKey string) (AnswerLibraryEntry, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return AnswerLibraryEntry{}, err
	}
	var e AnswerLibraryEntry
	err := s.db.QueryRowContext(ctx, `SELECT id, vendor_id, question_key, answer_json, effective_date, source_instance_id, status, updated_at, updated_by
		FROM answer_library WHERE vendor_id=? AND question_key=?`, vendorID, questionKey).
		Scan(&e.ID, &e.VendorID, &e.QuestionKey, &e.AnswerJSON, &e.EffectiveDate, &e.SourceInstanceID, &e.Status, &e.UpdatedAt, &e.UpdatedBy)
	if err != nil {
		return AnswerLibraryEntry{}, err
	}
	return e, nil
}
