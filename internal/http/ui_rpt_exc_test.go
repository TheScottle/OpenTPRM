package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/TheScottle/OpenTPRM/policies"
)

func testApp(t *testing.T) (*httpserver.App, http.Handler) {
	t.Helper()
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 41)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	text, err := policies.Base()
	if err != nil {
		t.Fatal(err)
	}
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	app := &httpserver.App{
		Cfg: cfg, Keyring: kr, Store: st, PDP: pdp, AllowDevHeaders: true, SealedMode: false,
		Idempotency: httpserver.NewIdempotencyStore(0),
	}
	return app, app.NewServer().Handler
}

func TestRPT_EXC_ReportsExportsExceptionsHTTP(t *testing.T) {
	app, h := testApp(t)
	_ = app
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

	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "ReportCo"}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)
	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{
		"relationship_owner": "ro",
	}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("eng: %d %s", w.Code, w.Body.String())
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	eid := eng["id"].(string)

	w = do(http.MethodPost, "/api/v1/exceptions", map[string]any{
		"engagement_id": eid, "scope": "residual MFA", "rationale": "monitor",
	}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("exc create: %d %s", w.Code, w.Body.String())
	}
	var exc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &exc)
	excID := exc["id"].(string)

	w = do(http.MethodGet, "/api/v1/exceptions", nil, "analyst1", "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("exc list: %d", w.Code)
	}

	// SOD-2: requester cannot approve
	w = do(http.MethodPost, "/api/v1/exceptions/"+excID+":approve", map[string]any{
		"residual_rating": "high", "conditions": []string{"monitor"}, "evidence_hashes": []string{},
	}, "analyst1", "approver")
	if w.Code != 403 {
		t.Fatalf("SOD-2 expected 403, got %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodPost, "/api/v1/exceptions/"+excID+":approve", map[string]any{
		"residual_rating": "high", "conditions": []string{"monitor"}, "evidence_hashes": []string{},
	}, "approver1", "approver")
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodGet, "/api/v1/reports/exceptions?classification=Privileged", nil, "analyst1", "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("report: %d %s", w.Code, w.Body.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if doc["marking"] == nil || !strings.Contains(doc["marking"].(string), "Privileged") {
		t.Fatalf("GEN-012 marking missing: %v", doc)
	}

	w = do(http.MethodPost, "/api/v1/exports", map[string]any{
		"format": "json", "scope": "exceptions", "classification": "Internal",
	}, "analyst1", "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}

	// Sensitive bulk without step-up
	w = do(http.MethodPost, "/api/v1/exports", map[string]any{
		"format": "csv", "scope": "all", "classification": "Privileged",
	}, "approver1", "approver")
	if w.Code != 401 {
		t.Fatalf("sensitive export without step-up: %d %s", w.Code, w.Body.String())
	}
}

func TestUI_AnalystHomeAndVendors(t *testing.T) {
	_, h := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-OpenTPRM-User", "analyst1")
	req.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "OpenTPRM") || !strings.Contains(w.Body.String(), "Analyst home") {
		t.Fatalf("home: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `/static/app.css`) {
		t.Fatal("expected CSP-safe external stylesheet")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/vendors", nil)
	req2.Header.Set("X-OpenTPRM-User", "analyst1")
	req2.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != 200 || !strings.Contains(w2.Body.String(), "Vendors") {
		t.Fatalf("vendors: %d %s", w2.Code, w2.Body.String())
	}
}

func TestOAuth_TokenIssueRequiresDPoP(t *testing.T) {
	_, h := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/oauth/token", strings.NewReader("grant_type=client_credentials&client_id=c1&scope=tprm.read"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:8443"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected DPoP required, got %d %s", w.Code, w.Body.String())
	}
	proof, _, err := authn.MintTestDPoPProof(http.MethodPost, "https://127.0.0.1:8443/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/oauth/token", strings.NewReader("grant_type=client_credentials&client_id=c1&scope=tprm.read"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = "127.0.0.1:8443"
	req2.Header.Set("DPoP", proof)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("token: %d %s", w2.Code, w2.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &tok)
	if tok["token_type"] != "DPoP" || tok["access_token"] == "" {
		t.Fatalf("token body: %v", tok)
	}
}
