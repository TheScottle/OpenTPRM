package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/crypto"
)

func TestAT_10_SealedWithoutMasterKey(t *testing.T) {
	k := crypto.NewSealed()
	if !k.Sealed() {
		t.Fatal("expected sealed")
	}
	if _, err := k.DBHexKey(); err != crypto.ErrSealed {
		t.Fatalf("expected ErrSealed, got %v", err)
	}
}

func TestUnsealFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	if err := crypto.GenerateMasterKey(path); err != nil {
		t.Fatal(err)
	}
	k := crypto.NewSealed()
	if err := k.UnsealFromFile(path); err != nil {
		t.Fatal(err)
	}
	if k.Sealed() {
		t.Fatal("expected unsealed")
	}
	hexKey, err := k.DBHexKey()
	if err != nil || len(hexKey) != 128 {
		t.Fatalf("bad hex key: %v %s", err, hexKey)
	}
	_ = os.Remove(path)
}
