package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/blob"
	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
	"github.com/google/uuid"
)

// UploadSession is a chunked upload row (M3 / EVD receive).
type UploadSession struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	Uploader     string `json:"uploader"`
	Status       string `json:"status"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	DeclaredName string `json:"declared_name"`
	MagicType    string `json:"magic_type"`
	CreatedAt    string `json:"created_at,omitempty"`
	TempPath     string `json:"-"`
}

// EvidenceRecord is a fuller evidence row used after :complete.
type EvidenceRecord struct {
	ID             string `json:"id"`
	EngagementID   string `json:"engagement_id"`
	UploadID       string `json:"upload_id"`
	EvidenceType   string `json:"evidence_type"`
	Status         string `json:"status"`
	BlobID         string `json:"blob_id"`
	SHA256         string `json:"sha256"`
	Classification string `json:"classification"`
	LicenseTag     string `json:"license_tag"`
	CreatedBy      string `json:"created_by"`
}

func (s *Store) uploadTmpDir() string {
	return filepath.Join(filepath.Dir(s.path), "uploads", "tmp")
}

// CreateUploadSession starts a chunked upload (POST /uploads).
func (s *Store) CreateUploadSession(ctx context.Context, u UploadSession) (UploadSession, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return UploadSession{}, err
	}
	if u.ID == "" {
		u.ID = uuid.Must(uuid.NewV7()).String()
	}
	if u.Status == "" {
		u.Status = "receiving"
	}
	now := nowUTC()
	u.CreatedAt = now
	if err := os.MkdirAll(s.uploadTmpDir(), 0o700); err != nil {
		return UploadSession{}, err
	}
	u.TempPath = filepath.Join(s.uploadTmpDir(), u.ID+".part")
	f, err := os.OpenFile(u.TempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return UploadSession{}, err
	}
	_ = f.Close()
	_, err = s.db.ExecContext(ctx, `INSERT INTO uploads(id, engagement_id, uploader, status, sha256, size_bytes, declared_name, magic_type, created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		u.ID, u.EngagementID, u.Uploader, u.Status, u.SHA256, u.SizeBytes, u.DeclaredName, u.MagicType, now)
	return u, err
}

// AppendUploadChunk streams a chunk onto the upload temp file (size-capped).
func (s *Store) AppendUploadChunk(ctx context.Context, uploadID string, r io.Reader, maxTotal int64) (UploadSession, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return UploadSession{}, err
	}
	u, err := s.GetUpload(ctx, uploadID)
	if err != nil {
		return UploadSession{}, err
	}
	if u.Status != "receiving" {
		return UploadSession{}, fmt.Errorf("upload not receiving")
	}
	path := filepath.Join(s.uploadTmpDir(), uploadID+".part")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return UploadSession{}, err
	}
	defer f.Close()
	st, _ := f.Stat()
	remaining := maxTotal - st.Size()
	if remaining <= 0 {
		return UploadSession{}, evidence.ErrSizeLimit
	}
	n, err := io.Copy(f, io.LimitReader(r, remaining+1))
	if err != nil {
		return UploadSession{}, err
	}
	if n > remaining {
		return UploadSession{}, evidence.ErrSizeLimit
	}
	u.SizeBytes = st.Size() + n
	u.TempPath = path
	_, err = s.db.ExecContext(ctx, `UPDATE uploads SET size_bytes=? WHERE id=?`, u.SizeBytes, uploadID)
	return u, err
}

// GetUpload loads an upload session.
func (s *Store) GetUpload(ctx context.Context, id string) (UploadSession, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return UploadSession{}, err
	}
	var u UploadSession
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, uploader, status, sha256, size_bytes, declared_name, magic_type, created_at
		FROM uploads WHERE id=?`, id).
		Scan(&u.ID, &u.EngagementID, &u.Uploader, &u.Status, &u.SHA256, &u.SizeBytes, &u.DeclaredName, &u.MagicType, &u.CreatedAt)
	if err != nil {
		return UploadSession{}, err
	}
	u.TempPath = filepath.Join(s.uploadTmpDir(), id+".part")
	return u, nil
}

// CompleteUpload validates magic/limits, stores an encrypted blob, and creates quarantined evidence.
func (s *Store) CompleteUpload(ctx context.Context, uploadID string, blobs *blob.Store, actor string) (EvidenceRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return EvidenceRecord{}, err
	}
	u, err := s.GetUpload(ctx, uploadID)
	if err != nil {
		return EvidenceRecord{}, err
	}
	if u.Status != "receiving" {
		return EvidenceRecord{}, fmt.Errorf("upload not receiving")
	}
	data, err := os.ReadFile(u.TempPath)
	if err != nil {
		return EvidenceRecord{}, err
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	ct, err := evidence.ValidateUpload(data)
	if err != nil {
		_, _ = s.db.ExecContext(ctx, `UPDATE uploads SET status=?, magic_type=?, sha256=? WHERE id=?`,
			"rejected", "", sha, uploadID)
		return EvidenceRecord{}, err
	}
	blobID := uuid.Must(uuid.NewV7()).String()
	if blobs != nil {
		if _, err := blobs.PutBytes(blobID, data); err != nil {
			return EvidenceRecord{}, err
		}
	}
	evID := uuid.Must(uuid.NewV7()).String()
	now := nowUTC()
	status, err := evidence.TransitionStatus(evidence.StatusReceived, evidence.StatusQuarantined)
	if err != nil {
		return EvidenceRecord{}, err
	}
	ev := EvidenceRecord{
		ID: evID, EngagementID: u.EngagementID, UploadID: uploadID,
		EvidenceType: string(ct), Status: string(status), BlobID: blobID,
		SHA256: sha, Classification: "Confidential", LicenseTag: "internal", CreatedBy: actor,
	}
	err = s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE uploads SET status=?, sha256=?, size_bytes=?, magic_type=? WHERE id=?`,
			"complete", sha, len(data), string(ct), uploadID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO evidence(id, engagement_id, upload_id, evidence_type, status, blob_id, sha256,
			license_tag, metadata_json, created_at, created_by, updated_at, updated_by, classification)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			ev.ID, ev.EngagementID, ev.UploadID, ev.EvidenceType, ev.Status, ev.BlobID, ev.SHA256,
			ev.LicenseTag, `{"channel":"staff_upload"}`, now, actor, now, actor, ev.Classification)
		return err
	})
	if err != nil {
		return EvidenceRecord{}, err
	}
	_ = os.Remove(u.TempPath)
	_ = time.Now()
	return ev, nil
}
