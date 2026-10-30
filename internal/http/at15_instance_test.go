package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAT_15_DeltaInstanceHTTPE2E(t *testing.T) {
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
	defer st.Close()
	text, err := policies.Base()
	if err != nil {
		t.Fatal(err)
	}
	pdp, err := authz.NewPDP(text)
	if err != nil {
		t.Fatal(err)
	}
	app := &httpserver.App{
		Keyring: kr, Store: st, PDP: pdp, AllowDevHeaders: true, SealedMode: false,
		Idempotency: httpserver.NewIdempotencyStore(0),
	}
	srv := app.NewServer()

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
		srv.Handler.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "Delta Vendor"}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("vendor %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)

	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{
		"relationship_owner": "ro", "service_description": "SaaS",
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("eng %d %s", w.Code, w.Body.String())
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	eid := eng["id"].(string)

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "seed", "opentprm-lite.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := authz.WithContext(context.Background(), authz.Context{
		PrincipalID: "editor1", PrincipalType: authz.PrincipalWorkforce, Roles: []string{"risk_analyst"}, AAL: 2,
	})
	_, ver, err := st.SeedTemplateFromJSON(ctx, raw, "editor1")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := st.PublishTemplateVersion(ctx, ver.ID, "publisher2")
	if err != nil {
		t.Fatal(err)
	}

	w = do(http.MethodPost, "/api/v1/questionnaire-instances", map[string]any{
		"template_version_id": pub.ID, "engagement_id": eid,
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("prior instance %d %s", w.Code, w.Body.String())
	}
	var priorWrap map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &priorWrap)
	prior := priorWrap["instance"].(map[string]any)
	priorID := prior["id"].(string)

	w = do(http.MethodPost, "/api/v1/questionnaire-instances/"+priorID+"/responses", map[string]any{
		"answers": map[string]any{"IAM-03": "yes", "GOV-01": "yes"},
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("responses %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodPost, "/api/v1/questionnaire-instances", map[string]any{
		"template_version_id": pub.ID, "engagement_id": eid, "delta_of": priorID,
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("delta instance %d %s", w.Code, w.Body.String())
	}
	var deltaWrap map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &deltaWrap)
	if deltaWrap["delta"] == nil {
		t.Fatal("expected AT-15 delta prefill on create")
	}
	deltaInst := deltaWrap["instance"].(map[string]any)
	deltaID := deltaInst["id"].(string)

	w = do(http.MethodGet, "/api/v1/questionnaire-instances/"+deltaID+":delta", nil, "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("delta get %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodPost, "/api/v1/questionnaire-instances/"+deltaID+"/reviews", map[string]any{
		"question_key": "GOV-01", "status": "accepted", "score": 1.0,
	}, "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("review %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodGet, "/api/v1/questionnaire-instances/"+deltaID+"/score", nil, "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("score %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodPost, "/api/v1/findings", map[string]any{
		"engagement_id": eid, "title": "Control gap", "severity": "medium",
	}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("finding %d %s", w.Code, w.Body.String())
	}

	w = do(http.MethodGet, "/api/v1/contracts", nil, "risk_analyst")
	if w.Code != 200 {
		t.Fatalf("contracts %d", w.Code)
	}
	w = do(http.MethodPost, "/api/v1/contracts", map[string]any{"engagement_id": eid, "title": "MSA"}, "risk_analyst")
	if w.Code != 201 {
		t.Fatalf("contract create %d %s", w.Code, w.Body.String())
	}
}
