package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestQST_InstanceResponseReviewAndAT15Delta(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "Q Co", Status: "active", CreatedBy: "a", UpdatedBy: "a"})
	eid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "ro", CreatedBy: "a", UpdatedBy: "a",
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "seed", "opentprm-lite.json"))
	if err != nil {
		t.Fatal(err)
	}
	tpl, ver, err := st.SeedTemplateFromJSON(ctx, raw, "editor1")
	if err != nil {
		t.Fatal(err)
	}
	_ = tpl
	pub, err := st.PublishTemplateVersion(ctx, ver.ID, "publisher1")
	if err != nil {
		t.Fatal(err)
	}

	prior, err := st.CreateQuestionnaireInstance(ctx, store.QuestionnaireInstance{
		TemplateVersionID: pub.ID, EngagementID: eid, CreatedBy: "analyst1", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	answers, _ := json.Marshal(map[string]any{"IAM-03": "yes", "GOV-01": "yes"})
	if _, err := st.AppendResponseRevision(ctx, prior.ID, "vendor1", string(answers)); err != nil {
		t.Fatal(err)
	}

	deltaInst, err := st.CreateQuestionnaireInstance(ctx, store.QuestionnaireInstance{
		TemplateVersionID: pub.ID, EngagementID: eid, DeltaOf: prior.ID,
		CreatedBy: "analyst1", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	prefill, err := st.DeltaPrefillForInstance(ctx, prior.ID, map[string]any{"IAM-03": "partial", "GOV-01": "yes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(prefill.ChangedKeys) != 1 || prefill.ChangedKeys[0] != "IAM-03" {
		t.Fatalf("delta changed=%v", prefill.ChangedKeys)
	}
	cur, _ := json.Marshal(map[string]any{"IAM-03": "partial", "GOV-01": "yes"})
	if _, err := st.AppendResponseRevision(ctx, deltaInst.ID, "vendor1", string(cur)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAnswerReview(ctx, store.AnswerReview{
		InstanceID: deltaInst.ID, QuestionKey: "IAM-03", Status: "accepted", Score: 0.5, Reviewer: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	sum, n, err := st.InstanceScore(ctx, deltaInst.ID)
	if err != nil || n != 1 || sum != 0.5 {
		t.Fatalf("score sum=%v n=%v err=%v", sum, n, err)
	}
	items, err := st.ListQuestionnaireInstances(ctx, eid)
	if err != nil || len(items) != 2 {
		t.Fatalf("list=%d err=%v", len(items), err)
	}
}

func TestEVD_EvidencePageAndSOCReview(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "Ev", Status: "active", CreatedBy: "a", UpdatedBy: "a"})
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateEngagement(ctx, store.Engagement{ID: eid, ThirdPartyID: vid, RelationshipOwner: "ro", CreatedBy: "a", UpdatedBy: "a"})

	// Minimal evidence row via upload path is heavy; insert via CreateFinding-like direct SQL not available.
	// Use upload complete for a real evidence id.
	u, err := st.CreateUploadSession(ctx, store.UploadSession{EngagementID: eid, Uploader: "a", DeclaredName: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("plain evidence text for pages")
	if _, err := st.AppendUploadChunk(ctx, u.ID, bytes.NewReader(payload), 1<<20); err != nil {
		t.Fatal(err)
	}
	// Complete without blob store is OK (blobs nil).
	ev, err := st.CompleteUpload(ctx, u.ID, nil, "a")
	if err != nil {
		t.Fatal(err)
	}
	page, err := st.PutEvidencePage(ctx, store.EvidencePage{
		EvidenceID: ev.ID, PageNum: 1, TextContent: "line1\x00<script>x</script>",
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.TextSHA256 == "" || page.TextContent == "line1\x00<script>x</script>" {
		t.Fatalf("sanitize failed: %#v", page)
	}
	got, err := st.GetEvidencePage(ctx, ev.ID, 1)
	if err != nil || got.TextSHA256 != page.TextSHA256 {
		t.Fatal(err)
	}
	rev, err := st.UpsertSOCReview(ctx, store.SOCReview{
		EvidenceID: ev.ID,
		ReviewJSON: `{"report_type":"SOC2_T2","service_org":"Acme","auditor":"Big4","period":{"start":"2024-01-01","end":"2024-12-31"},"opinion":"unmodified"}`,
		UpdatedBy:  "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := st.GetSOCReview(ctx, ev.ID)
	if err != nil || loaded.ID != rev.ID {
		t.Fatal(err)
	}
}

func TestM5_CatalogStoreBacked(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "Cat", Status: "active", CreatedBy: "a", UpdatedBy: "a"})
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateEngagement(ctx, store.Engagement{ID: eid, ThirdPartyID: vid, RelationshipOwner: "ro", CreatedBy: "a", UpdatedBy: "a"})

	f, err := st.CreateFinding(ctx, store.Finding{EngagementID: eid, Title: "Gap", Severity: "high"}, "analyst1")
	if err != nil || f.ID == "" {
		t.Fatal(err)
	}
	c, err := st.CreateContract(ctx, store.ContractRecord{EngagementID: eid, Title: "MSA", CreatedBy: "a", UpdatedBy: "a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateMonitoringSignal(ctx, store.MonitoringSignal{EngagementID: eid, Source: "news"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateSuggestion(ctx, store.Suggestion{Kind: "finding", PayloadJSON: `{"title":"x"}`})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateChangeRequest(ctx, store.ChangeRequest{
		Action: "update", TargetType: "vendor", TargetID: vid, PatchJSON: `{}`, PatchSHA256: "abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateAgentClient(ctx, store.AgentClient{Name: "bot", OwnerUserID: "admin", CreatedBy: "admin", UpdatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateModelEndpoint(ctx, store.ModelEndpoint{Name: "local", BaseURL: "http://127.0.0.1:8080", ModelName: "m", LocalFlag: true, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.CreateModel(ctx, store.ModelRecord{Name: "m", Version: "1", Digest: "sha256:x", License: "Apache-2.0"})
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := st.ListFindings(ctx)
	contracts, _ := st.ListContracts(ctx)
	if len(findings) != 1 || len(contracts) != 1 || c.Title != "MSA" {
		t.Fatalf("findings=%d contracts=%d", len(findings), len(contracts))
	}
}
