package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
	"github.com/google/uuid"
)

// EvidencePage is a derived safe-viewer page (EVD-007).
type EvidencePage struct {
	ID                 string `json:"id"`
	EvidenceID         string `json:"evidence_id"`
	PageNum            int    `json:"page_num"`
	TextContent        string `json:"text_content"`
	TextSHA256         string `json:"text_sha256"`
	ImageBlobID        string `json:"image_blob_id,omitempty"`
	HiddenTextDetected bool   `json:"hidden_text_detected"`
}

// SOCReview is a structured SOC review row (EVD-020).
type SOCReview struct {
	ID          string `json:"id"`
	EvidenceID  string `json:"evidence_id"`
	ReviewJSON  string `json:"review_json"`
	SignedOffBy string `json:"signed_off_by,omitempty"`
	SignedOffAt string `json:"signed_off_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	UpdatedBy   string `json:"updated_by"`
	RowVersion  int64  `json:"row_version,omitempty"`
}

// PutEvidencePage stores sanitized page text for the safe viewer.
func (s *Store) PutEvidencePage(ctx context.Context, p EvidencePage) (EvidencePage, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return EvidencePage{}, err
	}
	if p.EvidenceID == "" || p.PageNum < 1 {
		return EvidencePage{}, fmt.Errorf("evidence_id and page_num>=1 required")
	}
	safe := evidence.SanitizeViewerText(p.TextContent)
	sum := sha256.Sum256([]byte(safe))
	p.TextContent = safe
	p.TextSHA256 = hex.EncodeToString(sum[:])
	if p.ID == "" {
		p.ID = uuid.Must(uuid.NewV7()).String()
	}
	hidden := 0
	if p.HiddenTextDetected {
		hidden = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO evidence_pages(id, evidence_id, page_num, text_content, text_sha256, image_blob_id, hidden_text_detected)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(evidence_id, page_num) DO UPDATE SET
			text_content=excluded.text_content,
			text_sha256=excluded.text_sha256,
			image_blob_id=excluded.image_blob_id,
			hidden_text_detected=excluded.hidden_text_detected`,
		p.ID, p.EvidenceID, p.PageNum, p.TextContent, p.TextSHA256, p.ImageBlobID, hidden)
	return p, err
}

// ListEvidencePages lists pages for evidence (metadata + text for viewer stubs).
func (s *Store) ListEvidencePages(ctx context.Context, evidenceID string) ([]EvidencePage, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, evidence_id, page_num, text_content, text_sha256, image_blob_id, hidden_text_detected
		FROM evidence_pages WHERE evidence_id=? ORDER BY page_num`, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidencePage
	for rows.Next() {
		var p EvidencePage
		var hidden int
		if err := rows.Scan(&p.ID, &p.EvidenceID, &p.PageNum, &p.TextContent, &p.TextSHA256, &p.ImageBlobID, &hidden); err != nil {
			return nil, err
		}
		p.HiddenTextDetected = hidden != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetEvidencePage loads one page by evidence id + page number.
func (s *Store) GetEvidencePage(ctx context.Context, evidenceID string, pageNum int) (EvidencePage, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return EvidencePage{}, err
	}
	var p EvidencePage
	var hidden int
	err := s.db.QueryRowContext(ctx, `SELECT id, evidence_id, page_num, text_content, text_sha256, image_blob_id, hidden_text_detected
		FROM evidence_pages WHERE evidence_id=? AND page_num=?`, evidenceID, pageNum).
		Scan(&p.ID, &p.EvidenceID, &p.PageNum, &p.TextContent, &p.TextSHA256, &p.ImageBlobID, &hidden)
	if err != nil {
		return EvidencePage{}, err
	}
	p.HiddenTextDetected = hidden != 0
	return p, nil
}

// UpsertSOCReview stores structured SOC review JSON for evidence.
func (s *Store) UpsertSOCReview(ctx context.Context, rev SOCReview) (SOCReview, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return SOCReview{}, err
	}
	if rev.EvidenceID == "" || rev.ReviewJSON == "" {
		return SOCReview{}, fmt.Errorf("evidence_id and review_json required")
	}
	now := nowUTC()
	rev.UpdatedAt = now
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM soc_reviews WHERE evidence_id=?`, rev.EvidenceID).Scan(&existing)
	if err == sql.ErrNoRows {
		rev.ID = uuid.Must(uuid.NewV7()).String()
		_, err = s.db.ExecContext(ctx, `INSERT INTO soc_reviews(id, evidence_id, review_json, signed_off_by, signed_off_at, updated_at, updated_by)
			VALUES(?,?,?,?,?,?,?)`, rev.ID, rev.EvidenceID, rev.ReviewJSON, rev.SignedOffBy, rev.SignedOffAt, now, rev.UpdatedBy)
		return rev, err
	}
	if err != nil {
		return SOCReview{}, err
	}
	rev.ID = existing
	_, err = s.db.ExecContext(ctx, `UPDATE soc_reviews SET review_json=?, signed_off_by=?, signed_off_at=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
		rev.ReviewJSON, rev.SignedOffBy, rev.SignedOffAt, now, rev.UpdatedBy, rev.ID)
	return rev, err
}

// GetSOCReview loads SOC review by evidence id.
func (s *Store) GetSOCReview(ctx context.Context, evidenceID string) (SOCReview, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return SOCReview{}, err
	}
	var rev SOCReview
	err := s.db.QueryRowContext(ctx, `SELECT id, evidence_id, review_json, signed_off_by, signed_off_at, updated_at, updated_by, row_version
		FROM soc_reviews WHERE evidence_id=?`, evidenceID).
		Scan(&rev.ID, &rev.EvidenceID, &rev.ReviewJSON, &rev.SignedOffBy, &rev.SignedOffAt, &rev.UpdatedAt, &rev.UpdatedBy, &rev.RowVersion)
	return rev, err
}

// GetEvidenceRecord loads a fuller evidence row by id.
func (s *Store) GetEvidenceRecord(ctx context.Context, id string) (EvidenceRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return EvidenceRecord{}, err
	}
	var ev EvidenceRecord
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, upload_id, evidence_type, status, blob_id, sha256, classification, license_tag, created_by
		FROM evidence WHERE id=?`, id).
		Scan(&ev.ID, &ev.EngagementID, &ev.UploadID, &ev.EvidenceType, &ev.Status, &ev.BlobID, &ev.SHA256, &ev.Classification, &ev.LicenseTag, &ev.CreatedBy)
	return ev, err
}
