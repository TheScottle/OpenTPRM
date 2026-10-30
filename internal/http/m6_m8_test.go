package httpserver_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/config"
)

func TestOAuth_PKCEAuthorizeCodeAndToken(t *testing.T) {
	app, h := testApp(t)
	as := app.EnsureASForTest()
	_ = as.Clients.Register(authn.RegisteredClient{
		ID: "pre-reg", RedirectURIs: []string{"https://agent.example/cb"}, Public: true,
	})

	vb := make([]byte, 32)
	_, _ = rand.Read(vb)
	verifier := hex.EncodeToString(vb)
	challenge := authn.S256Challenge(verifier)

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code&client_id=pre-reg"+
		"&redirect_uri=https://agent.example/cb&code_challenge="+challenge+
		"&code_challenge_method=S256&scope=tprm.read&state=xyz", nil)
	req.Header.Set("X-OpenTPRM-User", "analyst1")
	req.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=xyz") {
		t.Fatalf("redirect: %s", loc)
	}
	code := loc[strings.Index(loc, "code=")+5:]
	if i := strings.IndexByte(code, '&'); i >= 0 {
		code = code[:i]
	}

	proof, _, err := authn.MintTestDPoPProof(http.MethodPost, "https://127.0.0.1:8443/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	form := "grant_type=authorization_code&client_id=pre-reg&redirect_uri=https://agent.example/cb&code=" +
		code + "&code_verifier=" + verifier
	req2 := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8443/oauth/token", strings.NewReader(form))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = "127.0.0.1:8443"
	req2.Header.Set("DPoP", proof)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("token: %d %s", w2.Code, w2.Body.String())
	}
}

func TestAT_05_ChangeRequestApprovalUI(t *testing.T) {
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
		"action": "update", "target_type": "finding", "target_id": "f1",
		"patch_json": `{"status":"open"}`, "patch_sha256": "abc", "rationale": "fix typo",
	}, "analyst1", "risk_analyst", false)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var cr map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &cr)
	id := cr["id"].(string)

	w = do(http.MethodGet, "/change-requests", nil, "approver1", "approver", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Change requests") || !strings.Contains(w.Body.String(), id) {
		t.Fatalf("ui: %d %s", w.Code, w.Body.String())
	}

	// Without step-up
	w = do(http.MethodPost, "/change-requests/"+id+":approve", nil, "approver1", "approver", false)
	if w.Code != 401 {
		t.Fatalf("step-up required: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPost, "/change-requests/"+id+":approve", nil, "approver1", "approver", true)
	if w.Code != http.StatusSeeOther && w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
}

func TestAI_ModelEndpointHTTPCRUD(t *testing.T) {
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
		r.Header.Set("X-OpenTPRM-User", "secadmin")
		r.Header.Set("X-OpenTPRM-Roles", "security_administrator")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(http.MethodPost, "/api/v1/model-endpoints", map[string]any{
		"name": "local", "base_url": "http://127.0.0.1:8080", "model_name": "m1", "local_flag": true,
	})
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var ep map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ep)
	id := ep["id"].(string)
	w = do(http.MethodGet, "/api/v1/model-endpoints/"+id, nil)
	if w.Code != 200 {
		t.Fatalf("get: %d", w.Code)
	}
	w = do(http.MethodPatch, "/api/v1/model-endpoints/"+id, map[string]any{"approved": true, "local_flag": true, "name": "local"})
	if w.Code != 200 {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodDelete, "/api/v1/model-endpoints/"+id, nil)
	if w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
}

func TestPortalEnabledWiresListener(t *testing.T) {
	app, _ := testApp(t)
	cfg := config.Default()
	cfg.Portal.Enabled = true
	cfg.Server.Portal.Enabled = true
	cfg.Server.Portal.Listen = "127.0.0.1:0"
	app.Cfg = cfg
	if !app.PortalEnabled() {
		t.Fatal("expected portal enabled")
	}
	ps := app.NewPortalServer()
	if ps == nil || ps.Handler == nil {
		t.Fatal("portal server missing")
	}
}
