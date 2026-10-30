package questionnaire

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var ErrTamperedPackage = errors.New("offline package rejected: locked cell or signature mismatch")

// Manifest is the signed metadata for an offline questionnaire package (QST / AT-07).
type Manifest struct {
	InstanceID  string    `json:"instance_id"`
	PinnedHash  string    `json:"pinned_hash"`
	Expiry      time.Time `json:"expiry"`
	LockedCells []string  `json:"locked_cells"`
	ContentSHA  string    `json:"content_sha256"`
	Format      string    `json:"format"` // "json"
}

// OfflinePackage is a signed export for vendors without portal access.
type OfflinePackage struct {
	Manifest     Manifest        `json:"manifest"`
	InstanceID   string          `json:"instance_id"`
	PinnedHash   string          `json:"pinned_hash"`
	Answers      json.RawMessage `json:"answers"`
	LockedCells  []string        `json:"locked_cells"`
	ContentHash  string          `json:"content_hash"`
	SignatureOK  bool            `json:"-"`
	OriginalLock map[string]any  `json:"-"` // locked cell values at pack time
}

// PackZip builds a signed offline zip: answers.json + locked.json + manifest.json + manifest.sig.
func PackZip(manifest Manifest, answers json.RawMessage, lockedOriginal map[string]any, priv ed25519.PrivateKey) ([]byte, error) {
	if manifest.InstanceID == "" || manifest.PinnedHash == "" {
		return nil, fmt.Errorf("manifest requires instance_id and pinned_hash")
	}
	if manifest.Format == "" {
		manifest.Format = "json"
	}
	if manifest.Expiry.IsZero() {
		manifest.Expiry = time.Now().UTC().Add(30 * 24 * time.Hour)
	}
	sum := sha256.Sum256(answers)
	manifest.ContentSHA = hex.EncodeToString(sum[:])

	lockedJSON, err := json.Marshal(lockedOriginal)
	if err != nil {
		return nil, err
	}
	manJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, manJSON)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string][]byte{
		"answers.json":  answers,
		"locked.json":   lockedJSON,
		"manifest.json": manJSON,
		"manifest.sig":  []byte(hex.EncodeToString(sig)),
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnpackZip verifies the Ed25519 signature and returns the package (AT-07).
func UnpackZip(data []byte, pub ed25519.PublicKey) (OfflinePackage, error) {
	if err := ValidateImportArchive(data); err != nil {
		return OfflinePackage{}, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return OfflinePackage{}, fmt.Errorf("%w: %v", ErrTamperedPackage, err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "./")
		rc, err := f.Open()
		if err != nil {
			return OfflinePackage{}, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 32<<20))
		_ = rc.Close()
		if err != nil {
			return OfflinePackage{}, err
		}
		files[name] = b
	}
	manJSON, ok := files["manifest.json"]
	if !ok {
		return OfflinePackage{}, fmt.Errorf("%w: missing manifest", ErrTamperedPackage)
	}
	sigHex, ok := files["manifest.sig"]
	if !ok {
		return OfflinePackage{}, fmt.Errorf("%w: missing signature", ErrTamperedPackage)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil || !ed25519.Verify(pub, manJSON, sig) {
		return OfflinePackage{}, fmt.Errorf("%w: bad signature", ErrTamperedPackage)
	}
	var man Manifest
	if err := json.Unmarshal(manJSON, &man); err != nil {
		return OfflinePackage{}, err
	}
	if !man.Expiry.IsZero() && time.Now().UTC().After(man.Expiry) {
		return OfflinePackage{}, fmt.Errorf("%w: package expired", ErrTamperedPackage)
	}
	answers := files["answers.json"]
	sum := sha256.Sum256(answers)
	if man.ContentSHA != "" && hex.EncodeToString(sum[:]) != man.ContentSHA {
		return OfflinePackage{}, fmt.Errorf("%w: content hash mismatch", ErrTamperedPackage)
	}
	var locked map[string]any
	if b := files["locked.json"]; len(b) > 0 {
		_ = json.Unmarshal(b, &locked)
	}
	pkg := OfflinePackage{
		Manifest:     man,
		InstanceID:   man.InstanceID,
		PinnedHash:   man.PinnedHash,
		Answers:      answers,
		LockedCells:  man.LockedCells,
		ContentHash:  man.ContentSHA,
		SignatureOK:  true,
		OriginalLock: locked,
	}
	return pkg, nil
}

// ImportOffline rejects whole-package when a locked cell was edited (AT-07).
func ImportOffline(pkg OfflinePackage, submitted map[string]any, original map[string]any) error {
	if !pkg.SignatureOK {
		return fmt.Errorf("%w: bad signature", ErrTamperedPackage)
	}
	if original == nil {
		original = pkg.OriginalLock
	}
	for _, key := range pkg.LockedCells {
		o, ok1 := original[key]
		s, ok2 := submitted[key]
		if !ok1 || !ok2 || fmt.Sprint(o) != fmt.Sprint(s) {
			return fmt.Errorf("%w: locked cell %s", ErrTamperedPackage, key)
		}
	}
	return nil
}
