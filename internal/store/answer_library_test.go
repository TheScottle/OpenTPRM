package store_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestQST_035_AnswerLibrary(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "LibCo", CreatedBy: "a", UpdatedBy: "a"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.UpsertAnswerLibrary(ctx, store.AnswerLibraryEntry{
		VendorID: vid, QuestionKey: "IAM-03", AnswerJSON: `"yes"`,
		SourceInstanceID: "qi-1", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.EffectiveDate == "" || got.Status != "accepted" {
		t.Fatalf("upsert: %+v", got)
	}
	list, err := st.ListAnswerLibrary(ctx, vid)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	got2, err := st.UpsertAnswerLibrary(ctx, store.AnswerLibraryEntry{
		VendorID: vid, QuestionKey: "IAM-03", AnswerJSON: `"no"`,
		SourceInstanceID: "qi-2", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got2.ID != got.ID || got2.AnswerJSON != `"no"` {
		t.Fatalf("replace: %+v", got2)
	}
	one, err := st.GetAnswerLibraryEntry(ctx, vid, "IAM-03")
	if err != nil || one.AnswerJSON != `"no"` {
		t.Fatalf("get: %+v %v", one, err)
	}
}
