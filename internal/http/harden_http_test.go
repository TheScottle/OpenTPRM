package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/blob"
	"github.com/TheScottle/OpenTPRM/internal/store"
)

func TestEVD_EvidencePageHTMLViewer(t *testing.T) {
	app, h := testApp(t)
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 9)
	}
	app.Blobs = &blob.Store{Root: t.TempDir(), KEK: kek}

	do := func(method, path string, body any) *httptest.ResponseRecorder {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("X-OpenTPRM-User", "analyst1")
		r.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "EvHTML"})
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)
	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{"relationship_owner": "ro"})
	if w.Code != 201 {
		t.Fatalf("eng: %d", w.Code)
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)

	ctx := authz.WithContext(httptest.NewRequest(http.MethodGet, "/", nil).Context(), authz.Context{
		PrincipalID: "analyst1", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"risk_analyst"}, AAL: 2,
	})
	u, err := app.Store.CreateUploadSession(ctx, store.UploadSession{
		EngagementID: eng["id"].(string), DeclaredName: "note.txt", Uploader: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("viewer html line")
	if _, err := app.Store.AppendUploadChunk(ctx, u.ID, bytes.NewReader(payload), 1<<20); err != nil {
		t.Fatal(err)
	}
	ev, err := app.Store.CompleteUpload(ctx, u.ID, app.Blobs, "analyst1")
	if err != nil {
		t.Fatal(err)
	}
	w = do(http.MethodPut, "/api/v1/evidence/"+ev.ID+"/pages", map[string]any{
		"page_num": 1, "text_content": "safe <script>no</script> text",
	})
	if w.Code != 200 {
		t.Fatalf("put page: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/evidence/"+ev.ID+"/pages/1/html", nil)
	if w.Code != 200 {
		t.Fatalf("html: %d %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type: %s", ct)
	}
	if strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "OpenTPRM safe viewer") {
		t.Fatalf("html body: %s", w.Body.String())
	}
}

func TestQST_035_AnswerLibraryHTTP(t *testing.T) {
	_, h := testApp(t)
	do := func(method, path string, body any, roles string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("X-OpenTPRM-User", "analyst1")
		r.Header.Set("X-OpenTPRM-Roles", roles)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "AnsLib"}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)
	w = do(http.MethodPost, "/api/v1/answer-library", map[string]any{
		"vendor_id": vid, "question_key": "GOV-01", "answer_json": `"yes"`,
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("upsert: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/answer-library?vendor_id="+vid, nil, "risk_analyst")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "GOV-01") {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
}

func TestRPT_004_ExportSecondApproverHTTP(t *testing.T) {
	_, h := testApp(t)
	do := func(method, path string, body any, user, roles string, stepUp bool) *httptest.ResponseRecorder {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("X-OpenTPRM-User", user)
		r.Header.Set("X-OpenTPRM-Roles", roles)
		if stepUp {
			r.Header.Set("X-OpenTPRM-StepUp", "1")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(http.MethodPost, "/api/v1/exports", map[string]any{
		"format": "json", "scope": "bulk", "classification": "Client-Confidential",
	}, "approver1", "approver", true)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var exp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &exp)
	id := exp["id"].(string)
	if exp["status"] != "pending_second_approval" {
		t.Fatalf("status: %v", exp["status"])
	}
	// SOD: requester cannot second-approve
	w = do(http.MethodPost, "/api/v1/exports/"+id+":approve", nil, "approver1", "approver", true)
	if w.Code != 403 {
		t.Fatalf("SOD want 403, got %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPost, "/api/v1/exports/"+id+":approve", nil, "approver2", "approver", true)
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &exp)
	if exp["status"] != "approved" || exp["second_approver"] != "approver2" {
		t.Fatalf("approved: %v", exp)
	}

	w = do(http.MethodGet, "/api/v1/reports/committee?classification=Client-Confidential", nil, "approver2", "approver", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "second approver") {
		t.Fatalf("committee: %d %s", w.Code, w.Body.String())
	}
}
