package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestQST_PublishAndSTD006Seeds(t *testing.T) {
	st, ctx := testStore(t)

	// Reject missing provenance
	if err := questionnaire.ValidateProvenanceJSON(`{}`); err == nil {
		t.Fatal("empty provenance must fail")
	}
	if err := questionnaire.ValidateProvenanceJSON(`{"source":"x","license":"proprietary","url":"https://x"}`); err == nil {
		t.Fatal("proprietary license must fail")
	}

	seedDir := filepath.Join("..", "..", "testdata", "seed")
	for _, name := range []string{"opentprm-core.json", "opentprm-lite.json", "opentprm-intake.json"} {
		raw, err := os.ReadFile(filepath.Join(seedDir, name))
		if err != nil {
			t.Fatal(err)
		}
		tpl, ver, err := st.SeedTemplateFromJSON(ctx, raw, "editor1")
		if err != nil {
			t.Fatalf("%s seed: %v", name, err)
		}
		if tpl.ID == "" || ver.Status != "draft" {
			t.Fatalf("%s: %+v %+v", name, tpl, ver)
		}
		// SOD: publisher must differ from last editor
		if _, err := st.PublishTemplateVersion(ctx, ver.ID, "editor1"); err != questionnaire.ErrSODViolation {
			t.Fatalf("%s same editor publish: %v", name, err)
		}
		pub, err := st.PublishTemplateVersion(ctx, ver.ID, "publisher2")
		if err != nil {
			t.Fatalf("%s publish: %v", name, err)
		}
		if pub.Status != "published" || pub.ContentHash == "" || pub.PublishedBy != "publisher2" {
			t.Fatalf("%s published record: %+v", name, pub)
		}
	}

	items, err := st.ListTemplates(ctx)
	if err != nil || len(items) < 3 {
		t.Fatalf("templates=%d err=%v", len(items), err)
	}

	// Manual create path
	tid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateTemplate(ctx, store.TemplateRecord{
		ID: tid, Name: "Extra", Kind: "overlay", CreatedBy: "e", UpdatedBy: "e",
	}); err != nil {
		t.Fatal(err)
	}
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateTemplateVersion(ctx, store.TemplateVersionRecord{
		ID: vid, TemplateID: tid, Semver: "0.1.0", Status: "draft",
		ContentJSON:    `{"questions":[]}`,
		ProvenanceJSON: `{"source":"Owner-authored","license":"owner_authored","url":"https://example.local"}`,
		LastEditor: "e", CreatedBy: "e", UpdatedBy: "e",
	}); err != nil {
		t.Fatal(err)
	}
}
