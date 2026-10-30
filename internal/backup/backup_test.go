package backup_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/TheScottle/OpenTPRM/internal/backup"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
)

func TestARC_013_RestoreVerifyOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "opentprm.db")
	if err := os.WriteFile(dbPath, []byte("sqlite-fake-payload-for-backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	m, err := backup.CreateOnlineSnapshot(dbPath, backupDir, []age.Recipient{id.Recipient()}, kr.SigningPriv)
	if err != nil {
		t.Fatal(err)
	}
	if m.Signature == "" || m.DBSHA256 == "" {
		t.Fatal("manifest incomplete")
	}
	manPath, err := backup.NewestManifest(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.VerifyOnly(manPath, kr.SigningPub); err != nil {
		t.Fatalf("VerifyOnly: %v", err)
	}
	got, err := backup.VerifyDrill(manPath, backupDir, kr.SigningPub, id)
	if err != nil {
		t.Fatalf("VerifyDrill: %v", err)
	}
	if got.DBSHA256 != m.DBSHA256 {
		t.Fatal("drill hash mismatch")
	}
	live := filepath.Join(dir, "live-data")
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatal("verify-only must not create live data dir")
	}
}
