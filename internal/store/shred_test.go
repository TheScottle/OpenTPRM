package store_test

import (
	"context"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestAT_14_ShredLeavesTombstone(t *testing.T) {
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := authz.WithContext(context.Background(), authz.Context{
		PrincipalID: "admin", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"system_administrator"}, AAL: 2,
	})
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "Acme", CreatedBy: "admin", UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	// Insert a vendor data key
	_, err = st.DB().Exec(`INSERT INTO vendor_data_keys(vendor_id, wrapped_key, created_at) VALUES(?,?,datetime('now'))`, vid, []byte("wrapped"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ShredVendor(ctx, vid, "admin", "retention"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.DB().QueryRow(`SELECT COUNT(1) FROM vendor_data_keys WHERE vendor_id=?`, vid).Scan(&n)
	if n != 0 {
		t.Fatal("AT-14: keys must be destroyed")
	}
	_ = st.DB().QueryRow(`SELECT COUNT(1) FROM tombstones WHERE object_id=?`, vid).Scan(&n)
	if n != 1 {
		t.Fatal("AT-14: tombstone required")
	}
}
