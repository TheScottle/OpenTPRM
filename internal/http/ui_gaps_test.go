package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUI_ExceptionListApprove(t *testing.T) {
	_, h := testApp(t)
	do := func(method, path string, body any, user, roles string) *httptest.ResponseRecorder {
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
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "Exc UI Co"}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)
	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{"relationship_owner": "ro"}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("eng: %d %s", w.Code, w.Body.String())
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	eid := eng["id"].(string)

	w = do(http.MethodPost, "/api/v1/exceptions", map[string]any{
		"engagement_id": eid, "scope": "UI residual", "rationale": "monitor",
	}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("exc: %d %s", w.Code, w.Body.String())
	}
	var exc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &exc)
	excID := exc["id"].(string)

	w = do(http.MethodGet, "/exceptions", nil, "analyst1", "risk_analyst")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "UI residual") || !strings.Contains(w.Body.String(), "Exceptions") {
		t.Fatalf("list ui: %d %s", w.Code, w.Body.String())
	}

	// SOD-2 via HTML approve
	form := strings.NewReader("residual_rating=high&conditions=monitor")
	req := httptest.NewRequest(http.MethodPost, "/exceptions/"+excID+":approve", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-OpenTPRM-User", "analyst1")
	req.Header.Set("X-OpenTPRM-Roles", "approver")
	wSOD := httptest.NewRecorder()
	h.ServeHTTP(wSOD, req)
	if wSOD.Code != 403 {
		t.Fatalf("SOD-2 ui want 403, got %d %s", wSOD.Code, wSOD.Body.String())
	}

	form2 := strings.NewReader("residual_rating=high&conditions=monitor")
	req2 := httptest.NewRequest(http.MethodPost, "/exceptions/"+excID+":approve", form2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("X-OpenTPRM-User", "approver1")
	req2.Header.Set("X-OpenTPRM-Roles", "approver")
	wOK := httptest.NewRecorder()
	h.ServeHTTP(wOK, req2)
	if wOK.Code != http.StatusSeeOther {
		t.Fatalf("approve ui: %d %s", wOK.Code, wOK.Body.String())
	}
}

func TestUI_AdminKeysBackupsAndAgentGrantsRevoke(t *testing.T) {
	_, h := testApp(t)
	do := func(method, path string, body any, user, roles string) *httptest.ResponseRecorder {
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
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodGet, "/admin/keys", nil, "secadmin", "security_administrator")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Admin keys") {
		t.Fatalf("keys ui: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/admin/backups", nil, "secadmin", "security_administrator")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Admin backups") {
		t.Fatalf("backups ui: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/admin/keys", nil, "analyst1", "risk_analyst")
	if w.Code != 403 {
		t.Fatalf("keys forbidden: %d", w.Code)
	}

	w = do(http.MethodPost, "/api/v1/agent-clients", map[string]any{
		"name": "my-bot", "owner_user_id": "analyst1",
	}, "secadmin", "security_administrator")
	if w.Code != 201 {
		t.Fatalf("agent client: %d %s", w.Code, w.Body.String())
	}
	var client map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &client)
	cid := client["id"].(string)

	w = do(http.MethodGet, "/me/agent-grants", nil, "analyst1", "risk_analyst")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "my-bot") {
		t.Fatalf("grants ui: %d %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/me/agent-grants/"+cid+":revoke", nil)
	req.Header.Set("X-OpenTPRM-User", "analyst1")
	req.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	wRev := httptest.NewRecorder()
	h.ServeHTTP(wRev, req)
	if wRev.Code != http.StatusSeeOther {
		t.Fatalf("revoke ui: %d %s", wRev.Code, wRev.Body.String())
	}

	w = do(http.MethodGet, "/api/v1/me/agent-grants", nil, "analyst1", "risk_analyst")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "revoked") {
		t.Fatalf("grants api: %d %s", w.Code, w.Body.String())
	}
}
