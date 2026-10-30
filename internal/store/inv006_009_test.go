package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestINV_006_TagsAndCustomFields(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{
		ID: vid, LegalName: "Tagged Co", TagsJSON: `["saas","critical"]`,
		CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateTagsJSON(`["ok"]`); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateTagsJSON(`not-array`); err == nil {
		t.Fatal("invalid tags must fail")
	}

	def := store.CustomFieldDef{
		ID: uuid.Must(uuid.NewV7()).String(), ObjectType: "third_party",
		FieldKey: "contract_vehicle", FieldType: "enum",
		EnumValues: []string{"msa", "sow"}, CreatedBy: "a",
	}
	if err := st.CreateCustomFieldDef(ctx, def); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCustomFieldValue(ctx, store.CustomFieldValue{
		ObjectType: "third_party", ObjectID: vid, DefID: def.ID,
		ValueJSON: `"bogus"`, UpdatedBy: "a",
	}); err == nil {
		t.Fatal("enum mismatch must fail")
	}
	if err := st.SetCustomFieldValue(ctx, store.CustomFieldValue{
		ObjectType: "third_party", ObjectID: vid, DefID: def.ID,
		ValueJSON: `"msa"`, UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	vals, err := st.ListCustomFieldValues(ctx, "third_party", vid)
	if err != nil || len(vals) != 1 || vals[0].FieldKey != "contract_vehicle" {
		t.Fatalf("values=%+v err=%v", vals, err)
	}

	// Cap at 50 defs
	for i := 0; i < store.MaxCustomFieldsPerType; i++ {
		d := store.CustomFieldDef{
			ID: uuid.Must(uuid.NewV7()).String(), ObjectType: "engagement",
			FieldKey:   fmt.Sprintf("field_%d_%s", i, uuid.Must(uuid.NewV7()).String()),
			FieldType: "string", CreatedBy: "a",
		}
		if err := st.CreateCustomFieldDef(ctx, d); err != nil {
			t.Fatalf("def %d: %v", i, err)
		}
	}
	if err := st.CreateCustomFieldDef(ctx, store.CustomFieldDef{
		ID: uuid.Must(uuid.NewV7()).String(), ObjectType: "engagement",
		FieldKey: "overflow", FieldType: "string", CreatedBy: "a",
	}); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("want max error, got %v", err)
	}
}

func TestINV_009_NextActionDueEarliest(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "Due Co", CreatedBy: "a", UpdatedBy: "a"})
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "ro",
		RenewalDate: "2027-12-01", CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEngagementReassessmentDue(ctx, eid, "2027-06-01"); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvidenceExpiring(ctx, uuid.Must(uuid.NewV7()).String(), eid, "2027-03-15", "a"); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertFindingDue(ctx, uuid.Must(uuid.NewV7()).String(), eid, "2027-01-10", "a"); err != nil {
		t.Fatal(err)
	}
	due, err := st.RecalculateNextActionDue(ctx, eid)
	if err != nil {
		t.Fatal(err)
	}
	if due != "2027-01-10" {
		t.Fatalf("INV-009 earliest due want 2027-01-10 got %q", due)
	}
	engs, err := st.ListEngagementsByVendor(ctx, vid)
	if err != nil || len(engs) != 1 || engs[0].NextActionDue != "2027-01-10" {
		t.Fatalf("persisted next_action_due=%v err=%v", engs, err)
	}
	if got := store.EarliestDue("2028-01-01", "", "2026-05-01", "not-a-date"); got != "2026-05-01" {
		t.Fatalf("EarliestDue=%q", got)
	}
}
