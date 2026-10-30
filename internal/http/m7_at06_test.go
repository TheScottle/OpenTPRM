package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAT_06_StaleChangeRequestHTTP(t *testing.T) {
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
	w := do(http.MethodPost, "/api/v1/change-requests", map[string]any{
		"action": "due_date_set", "target_type": "finding", "target_id": "f1",
		"patch_json": `{"due":"2026-02-01"}`, "patch_sha256": "x", "target_etag": "v1",
		"rationale": "extend",
	}, "analyst1", "risk_analyst", false)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var cr map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &cr)
	id := cr["id"].(string)

	w = do(http.MethodPost, "/api/v1/change-requests/"+id+":approve", map[string]any{
		"current_etag": "v2",
	}, "approver1", "approver", true)
	if w.Code != 409 {
		t.Fatalf("AT-06 want 409 stale, got %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPost, "/api/v1/change-requests/"+id+":approve", map[string]any{
		"current_etag": "v1",
	}, "approver1", "approver", true)
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
}

func TestUI_IntakeAnalystQueue(t *testing.T) {
	_, h := testApp(t)
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
	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "IntakeCo"})
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)
	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{"relationship_owner": "ro"})
	if w.Code != 201 {
		t.Fatalf("eng: %d %s", w.Code, w.Body.String())
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	w = do(http.MethodPost, "/api/v1/intakes", map[string]any{
		"engagement_id": eng["id"], "answers_json": `{"data_sensitivity":"high"}`,
	})
	if w.Code != 201 {
		t.Fatalf("intake: %d %s", w.Code, w.Body.String())
	}
	var intake map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &intake)
	iid := intake["id"].(string)

	w = do(http.MethodGet, "/intakes", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Intake queue") || !strings.Contains(w.Body.String(), iid) {
		t.Fatalf("ui: %d %s", w.Code, w.Body.String())
	}
}

func TestAI_SuggestionAcceptCitationHTTP(t *testing.T) {
	_, h := testApp(t)
	do := func(method, path string, body any, roles string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-OpenTPRM-User", "approver1")
		r.Header.Set("X-OpenTPRM-Roles", roles)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(http.MethodPost, "/api/v1/suggestions", map[string]any{
		"kind": "soc_field", "payload_json": `{"ok":true}`,
		"citations_json": `[{"source_id":"ev1","quote":"encrypts data at rest","page":1}]`,
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var sug map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &sug)
	id := sug["id"].(string)
	w = do(http.MethodPost, "/api/v1/suggestions/"+id+":accept", map[string]any{
		"source_text": "unrelated",
	}, "approver")
	if w.Code != 409 {
		t.Fatalf("unverified want 409, got %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPost, "/api/v1/suggestions/"+id+":accept", map[string]any{
		"source_text": "The vendor encrypts data at rest using AES-256.",
	}, "approver")
	if w.Code != 200 {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
}
