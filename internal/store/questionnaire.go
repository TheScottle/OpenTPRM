package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
	"github.com/google/uuid"
)

// TemplateRecord is a questionnaire_templates row.
type TemplateRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	CreatedBy string `json:"created_by"`
	UpdatedBy string `json:"updated_by"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	RowVersion int64 `json:"row_version,omitempty"`
}

// TemplateVersionRecord is a template_versions row.
type TemplateVersionRecord struct {
	ID             string `json:"id"`
	TemplateID     string `json:"template_id"`
	Semver         string `json:"semver"`
	Status         string `json:"status"`
	ContentHash    string `json:"content_hash"`
	ContentJSON    string `json:"content_json"`
	ProvenanceJSON string `json:"provenance_json"`
	LastEditor     string `json:"last_editor"`
	PublishedBy    string `json:"published_by"`
	PublishedAt    string `json:"published_at,omitempty"`
	CreatedBy      string `json:"created_by"`
	UpdatedBy      string `json:"updated_by"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	RowVersion     int64  `json:"row_version,omitempty"`
}

// CreateTemplate inserts a questionnaire template shell.
func (s *Store) CreateTemplate(ctx context.Context, t TemplateRecord) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	if t.Kind == "" {
		t.Kind = "core"
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO questionnaire_templates(id, name, kind, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?)`, t.ID, t.Name, t.Kind, now, t.CreatedBy, now, t.UpdatedBy)
	return err
}

// CreateTemplateVersion inserts a draft version (content + STD-006 provenance required).
func (s *Store) CreateTemplateVersion(ctx context.Context, v TemplateVersionRecord) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	if v.Status == "" {
		v.Status = "draft"
	}
	if v.ContentJSON == "" {
		v.ContentJSON = "{}"
	}
	if v.ProvenanceJSON == "" {
		v.ProvenanceJSON = "{}"
	}
	if err := questionnaire.ValidateProvenanceJSON(v.ProvenanceJSON); err != nil {
		return err
	}
	now := nowUTC()
	if v.ID == "" {
		v.ID = uuid.Must(uuid.NewV7()).String()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO template_versions(
		id, template_id, semver, status, content_hash, content_json, provenance_json, last_editor,
		created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.ID, v.TemplateID, v.Semver, v.Status, v.ContentHash, v.ContentJSON, v.ProvenanceJSON, v.LastEditor,
		now, v.CreatedBy, now, v.UpdatedBy)
	return err
}

// GetTemplateVersion loads one version.
func (s *Store) GetTemplateVersion(ctx context.Context, id string) (TemplateVersionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return TemplateVersionRecord{}, err
	}
	var v TemplateVersionRecord
	err := s.db.QueryRowContext(ctx, `SELECT id, template_id, semver, status, content_hash, content_json, provenance_json,
		last_editor, published_by, published_at, created_by, updated_by, created_at, updated_at, row_version
		FROM template_versions WHERE id=?`, id).
		Scan(&v.ID, &v.TemplateID, &v.Semver, &v.Status, &v.ContentHash, &v.ContentJSON, &v.ProvenanceJSON,
			&v.LastEditor, &v.PublishedBy, &v.PublishedAt, &v.CreatedBy, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt, &v.RowVersion)
	return v, err
}

// ListTemplateVersions lists versions for a template.
func (s *Store) ListTemplateVersions(ctx context.Context, templateID string) ([]TemplateVersionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, template_id, semver, status, content_hash, content_json, provenance_json,
		last_editor, published_by, published_at, created_by, updated_by, created_at, updated_at, row_version
		FROM template_versions WHERE template_id=? ORDER BY created_at`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TemplateVersionRecord
	for rows.Next() {
		var v TemplateVersionRecord
		if err := rows.Scan(&v.ID, &v.TemplateID, &v.Semver, &v.Status, &v.ContentHash, &v.ContentJSON, &v.ProvenanceJSON,
			&v.LastEditor, &v.PublishedBy, &v.PublishedAt, &v.CreatedBy, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt, &v.RowVersion); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PublishTemplateVersion applies QST-001/002 SOD publish and freezes content hash.
func (s *Store) PublishTemplateVersion(ctx context.Context, versionID, publisher string) (TemplateVersionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return TemplateVersionRecord{}, err
	}
	v, err := s.GetTemplateVersion(ctx, versionID)
	if err != nil {
		return TemplateVersionRecord{}, err
	}
	if err := questionnaire.ValidateProvenanceJSON(v.ProvenanceJSON); err != nil {
		return TemplateVersionRecord{}, err
	}
	var prov map[string]string
	_ = json.Unmarshal([]byte(v.ProvenanceJSON), &prov)
	tv := questionnaire.TemplateVersion{
		TemplateID: v.TemplateID,
		Semver:     v.Semver,
		Status:     v.Status,
		Content:    json.RawMessage(v.ContentJSON),
		LastEditor: v.LastEditor,
		Provenance: prov,
	}
	published, err := questionnaire.Publish(tv, publisher)
	if err != nil {
		return TemplateVersionRecord{}, err
	}
	now := nowUTC()
	err = s.WithWrite(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE template_versions SET status=?, content_hash=?, published_by=?, published_at=?, updated_at=?, updated_by=?, row_version=row_version+1
			WHERE id=? AND status='draft'`,
			published.Status, published.ContentHash, publisher, now, now, publisher, versionID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("publish raced or not draft")
		}
		return nil
	})
	if err != nil {
		return TemplateVersionRecord{}, err
	}
	return s.GetTemplateVersion(ctx, versionID)
}

// SeedTemplateFromJSON creates template + draft version from a seed document with STD-006 provenance.
func (s *Store) SeedTemplateFromJSON(ctx context.Context, raw []byte, actor string) (TemplateRecord, TemplateVersionRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return TemplateRecord{}, TemplateVersionRecord{}, err
	}
	var doc struct {
		Name       string            `json:"name"`
		Kind       string            `json:"kind"`
		Semver     string            `json:"semver"`
		Provenance map[string]string `json:"provenance"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return TemplateRecord{}, TemplateVersionRecord{}, err
	}
	provJSON, _ := json.Marshal(doc.Provenance)
	if err := questionnaire.ValidateProvenanceJSON(string(provJSON)); err != nil {
		return TemplateRecord{}, TemplateVersionRecord{}, err
	}
	t := TemplateRecord{
		ID: uuid.Must(uuid.NewV7()).String(), Name: doc.Name, Kind: doc.Kind,
		CreatedBy: actor, UpdatedBy: actor,
	}
	if err := s.CreateTemplate(ctx, t); err != nil {
		return TemplateRecord{}, TemplateVersionRecord{}, err
	}
	v := TemplateVersionRecord{
		ID: uuid.Must(uuid.NewV7()).String(), TemplateID: t.ID, Semver: doc.Semver,
		Status: "draft", ContentJSON: string(raw), ProvenanceJSON: string(provJSON),
		LastEditor: actor, CreatedBy: actor, UpdatedBy: actor,
	}
	if err := s.CreateTemplateVersion(ctx, v); err != nil {
		return TemplateRecord{}, TemplateVersionRecord{}, err
	}
	return t, v, nil
}
