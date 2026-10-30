package audit_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/store"
)

func TestAT_11_AuditChainDetectsTamper(t *testing.T) {
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := store.Open(dir, kr)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	al := audit.New(st.DB(), kr)
	ctx := authz.WithContext(context.Background(), authz.Context{
		PrincipalID: "u1", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"auditor"}, AAL: 2,
	})
	if err := al.Append(ctx, audit.Event{Action: "test", ResourceType: "system", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := al.Append(ctx, audit.Event{Action: "test2", ResourceType: "system", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	res, err := al.Verify(ctx)
	if err != nil || !res.OK {
		t.Fatalf("expected ok chain: %+v %v", res, err)
	}

	// Tamper by disabling trigger via raw recreate — SQLite triggers block UPDATE.
	// Simulate offline edit by writing a second connection that replaces the table content using backup approach:
	// Delete triggers, update hash, recreate — or use ATTACH. Simpler: exec UPDATE after dropping trigger.
	db := st.DB()
	_, _ = db.Exec(`DROP TRIGGER IF EXISTS audit_events_no_update`)
	_, err = db.Exec(`UPDATE audit_events SET action='tampered' WHERE action='test2'`)
	if err != nil {
		t.Fatal(err)
	}
	res, err = al.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("AT-11: expected chain failure after tamper")
	}
	_ = filepath.Join(dir, "opentprm.db")
	_ = sql.ErrNoRows
}
