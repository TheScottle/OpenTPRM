package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func testStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := authz.WithContext(context.Background(), authz.Context{
		PrincipalID: "analyst1", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"risk_analyst"}, AAL: 2,
	})
	return st, ctx
}

func TestINV_001_VendorFieldsPersisted(t *testing.T) {
	st, ctx := testStore(t)
	id := uuid.Must(uuid.NewV7()).String()
	v := store.Vendor{
		ID: id, LegalName: "Acme Risk LLC", AliasesJSON: `["Acme"]`, LEI: "5493001KJTIIGC8Y1R12",
		Country: "US", HQAddress: "1 Main", DomainsJSON: `["acme.example"]`,
		PublicPrivate: "private", Regulated: true, Status: "active", Tier: 2,
		TagsJSON: `["saas"]`, CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}
	if err := st.CreateVendor(ctx, v); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetVendor(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.LegalName != v.LegalName || got.LEI != v.LEI || !got.Regulated || got.Status != "active" {
		t.Fatalf("INV-001 fields mismatch: %+v", got)
	}
}

func TestINV_002_DuplicateDetectAndMerge(t *testing.T) {
	st, ctx := testStore(t)
	a := store.Vendor{ID: uuid.Must(uuid.NewV7()).String(), LegalName: "Foo Bar Inc", DomainsJSON: `["foo.example"]`, LEI: "ABC", CreatedBy: "a", UpdatedBy: "a"}
	b := store.Vendor{ID: uuid.Must(uuid.NewV7()).String(), LegalName: "foo-bar inc", DomainsJSON: `["foo.example"]`, LEI: "abc", CreatedBy: "a", UpdatedBy: "a"}
	if err := st.CreateVendor(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVendor(ctx, b); err != nil {
		t.Fatal(err)
	}
	dups, err := st.FindDuplicateVendors(ctx, "FOO BAR INC", `["foo.example"]`, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(dups) < 2 {
		t.Fatalf("expected duplicates, got %d", len(dups))
	}
	if err := st.MergeVendors(ctx, a.ID, b.ID, "analyst1", "duplicate cleanup"); err != nil {
		t.Fatal(err)
	}
	src, err := st.GetVendor(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if src.Status != "terminated" {
		t.Fatalf("merged source status=%s", src.Status)
	}
	hist, err := st.ListHistory(ctx, "third_party", a.ID)
	if err != nil || len(hist) == 0 {
		t.Fatalf("merge history missing: %v %d", err, len(hist))
	}
}

func TestINV_003_004_005_EngagementsContactsFourthParties(t *testing.T) {
	st, ctx := testStore(t)
	v1 := uuid.Must(uuid.NewV7()).String()
	v2 := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: v1, LegalName: "VendorA", CreatedBy: "a", UpdatedBy: "a"})
	_ = st.CreateVendor(ctx, store.Vendor{ID: v2, LegalName: "FourthParty", CreatedBy: "a", UpdatedBy: "a"})

	eid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: v1, RelationshipOwner: "ro1",
		ServiceDescription: "Payroll", AccessTypesJSON: `["network"]`,
		VendorAIUse: "no", CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	engs, err := st.ListEngagementsByVendor(ctx, v1)
	if err != nil || len(engs) != 1 {
		t.Fatalf("engagements: %v %d", err, len(engs))
	}
	if err := st.ComputeNextActionDue(ctx, eid, "2027-01-01"); err != nil {
		t.Fatal(err)
	}

	cid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateContact(ctx, store.VendorContact{
		ID: cid, ThirdPartyID: v1, Role: "security", Name: "Pat", Email: "pat@vendor.example",
		LastVerified: "2026-10-01", CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	contacts, err := st.ListContacts(ctx, v1)
	if err != nil || len(contacts) != 1 || contacts[0].Role != "security" {
		t.Fatalf("contacts: %+v %v", contacts, err)
	}

	lid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateFourthPartyLink(ctx, store.FourthPartyLink{
		ID: lid, FromThirdPartyID: v1, ToThirdPartyID: v2, Role: "subprocessor",
		Source: "soc_carve_out", CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	conc, err := st.FourthPartyConcentration(ctx)
	if err != nil || conc[v2] != 1 {
		t.Fatalf("concentration: %v %v", conc, err)
	}
}

func TestINV_007_UpdateWritesHistory(t *testing.T) {
	st, ctx := testStore(t)
	id := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: id, LegalName: "Before", CreatedBy: "a", UpdatedBy: "a"})
	v, _ := st.GetVendor(ctx, id)
	v.LegalName = "After"
	v.UpdatedBy = "a"
	if err := st.UpdateVendor(ctx, v, "rename"); err != nil {
		t.Fatal(err)
	}
	hist, err := st.ListHistory(ctx, "third_party", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) < 2 {
		t.Fatalf("want create+update history, got %d", len(hist))
	}
}

func TestINV_008_BulkCSVRejectsFormulas(t *testing.T) {
	st, ctx := testStore(t)
	csv := "legal_name,domain,lei,country,status\n" +
		"Good Co,good.example,,US,prospect\n" +
		"=CMD(),evil.example,,US,prospect\n"
	res, err := st.BulkImportVendorsCSV(ctx, strings.NewReader(csv), "analyst1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("rows=%d", len(res))
	}
	if !res[0].OK || res[1].OK {
		t.Fatalf("expected first ok second fail: %+v", res)
	}
	if !strings.Contains(res[1].Error, "formula") {
		t.Fatalf("error=%s", res[1].Error)
	}
}

func TestINV_002_NormalizeKey(t *testing.T) {
	a := store.NormalizeVendorKey("Foo-Bar Inc.", "FOO.EXAMPLE", "lei1")
	b := store.NormalizeVendorKey("foo bar inc", "foo.example", "LEI1")
	if a != b {
		t.Fatalf("%q != %q", a, b)
	}
}
