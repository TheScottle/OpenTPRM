package backup

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// Manifest describes a signed backup (ARC-010).
type Manifest struct {
	CreatedAt string            `json:"created_at"`
	DBSHA256  string            `json:"db_sha256"`
	Files     map[string]string `json:"files"`
	Signature string            `json:"signature,omitempty"`
}

// CreateOnlineSnapshot copies dbPath into backupDir and age-encrypts to recipients.
func CreateOnlineSnapshot(dbPath, backupDir string, recipients []age.Recipient, signPriv ed25519.PrivateKey) (Manifest, error) {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return Manifest{}, err
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(raw)
	name := fmt.Sprintf("db-%s.sqlite.age", time.Now().UTC().Format("20060102T150405"))
	outPath := filepath.Join(backupDir, name)
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return Manifest{}, err
	}
	w, err := age.Encrypt(f, recipients...)
	if err != nil {
		_ = f.Close()
		return Manifest{}, err
	}
	if _, err := w.Write(raw); err != nil {
		_ = w.Close()
		_ = f.Close()
		return Manifest{}, err
	}
	_ = w.Close()
	_ = f.Close()

	m := Manifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		DBSHA256:  hex.EncodeToString(sum[:]),
		Files:     map[string]string{name: hex.EncodeToString(sum[:])},
	}
	body, err := canonicalManifest(m)
	if err != nil {
		return Manifest{}, err
	}
	sig := ed25519.Sign(signPriv, body)
	m.Signature = hex.EncodeToString(sig)
	manPath := filepath.Join(backupDir, "manifest-"+time.Now().UTC().Format("20060102T150405")+".json")
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(manPath, mb, 0o600); err != nil {
		return m, err
	}
	return m, nil
}

func canonicalManifest(m Manifest) ([]byte, error) {
	check := Manifest{CreatedAt: m.CreatedAt, DBSHA256: m.DBSHA256, Files: m.Files}
	return json.Marshal(check)
}

// VerifyOnly checks manifest signature without restoring (ARC-013).
func VerifyOnly(manifestPath string, pub ed25519.PublicKey) error {
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	return VerifyManifest(m, pub)
}

// LoadManifest reads a manifest JSON file.
func LoadManifest(manifestPath string) (Manifest, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// VerifyManifest checks the Ed25519 signature over the canonical payload.
func VerifyManifest(m Manifest, pub ed25519.PublicKey) error {
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return err
	}
	body, err := canonicalManifest(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("manifest signature invalid")
	}
	return nil
}

// VerifyDrill decrypts each age file listed in the manifest with identity,
// checks SHA-256 against the manifest, and does not write into a live data dir (ARC-012/013).
func VerifyDrill(manifestPath, backupDir string, pub ed25519.PublicKey, identity age.Identity) (Manifest, error) {
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if err := VerifyManifest(m, pub); err != nil {
		return Manifest{}, err
	}
	for name, wantHex := range m.Files {
		path := filepath.Join(backupDir, name)
		plain, err := decryptFile(path, identity)
		if err != nil {
			return Manifest{}, fmt.Errorf("decrypt %s: %w", name, err)
		}
		sum := sha256.Sum256(plain)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, wantHex) {
			return Manifest{}, fmt.Errorf("hash mismatch for %s", name)
		}
		if name == filepath.Base(name) && strings.HasPrefix(name, "db-") && !strings.EqualFold(got, m.DBSHA256) {
			return Manifest{}, fmt.Errorf("db hash mismatch")
		}
	}
	return m, nil
}

func decryptFile(path string, identity age.Identity) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// WriteManifestPath returns the newest manifest-*.json under dir, or error.
func NewestManifest(backupDir string) (string, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return "", err
	}
	var newest string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "manifest-") && strings.HasSuffix(name, ".json") {
			if name > newest {
				newest = name
			}
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no manifest in %s", backupDir)
	}
	return filepath.Join(backupDir, newest), nil
}
