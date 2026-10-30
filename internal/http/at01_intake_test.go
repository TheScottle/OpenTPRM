package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/TheScottle/OpenTPRM/policies"
)

func TestAT_01_IntakeSubmitHTTPE2E(t *testing.T) {
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 33)
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

	do := func(method, path string, body any, idem string) *httptest.ResponseRecorder {
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
		if idem != "" {
			r.Header.Set("Idempotency-Key", idem)
		}
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "Priv Access LLC"}, "at01-vendor")
	if w.Code != 201 {
		t.Fatalf("vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)

	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{
		"relationship_owner": "ro", "service_description": "Privileged SaaS",
	}, "at01-eng")
	if w.Code != 201 {
		t.Fatalf("engagement: %d %s", w.Code, w.Body.String())
	}
	var eng map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &eng)
	eid := eng["id"].(string)

	factors, _ := json.Marshal(map[string]any{
		"data_sensitivity": 5, "client_confidential": true, "privileged_access": 4,
		"operational_criticality": 3, "regulatory_exposure": 3, "system_access": 3,
		"data_volume": 3, "external_impact": 2, "vendor_ai_use": 2,
		"fourth_party_reliance": 2, "financial_dependency": 2, "jurisdiction": 2,
		"substitutability": 3,
	})
	w = do(http.MethodPost, "/api/v1/intakes", map[string]any{
		"engagement_id": eid,
		"answers_json":  `{"privileged_access":"yes","client_confidential":true,"highest_classification":"Client-Confidential"}`,
		"factor_scores_json": string(factors),
	}, "at01-intake")
	if w.Code != 201 {
		t.Fatalf("intake create: %d %s", w.Code, w.Body.String())
	}
	var intake map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &intake)
	iid := intake["id"].(string)

	w = do(http.MethodPost, "/api/v1/intakes/"+iid+":submit", map[string]any{}, "at01-submit")
	if w.Code != 200 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	tier, _ := result["tier"].(float64)
	if int(tier) > 2 {
		t.Fatalf("AT-01: expected tier <= 2, got %v floors=%v", result["tier"], result["floors"])
	}
	plan, _ := result["plan"].(map[string]any)
	if plan["assurance"] != true {
		t.Fatalf("AT-01: plan must request independent assurance: %+v", plan)
	}

	// Idempotency replay
	w2 := do(http.MethodPost, "/api/v1/intakes/"+iid+":submit", map[string]any{}, "at01-submit")
	if w2.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("expected idempotent replay header, got %d %v", w2.Code, w2.Header())
	}
}

func TestSEC_AZ_001_ProductionDevHeadersRefused(t *testing.T) {
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 44)
	}
	_ = kr.Unseal(key)
	st, err := store.Open(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	text, _ := policies.Base()
	pdp, _ := authz.NewPDP(text)
	app := &httpserver.App{Keyring: kr, Store: st, PDP: pdp, AllowDevHeaders: false, SealedMode: false}
	srv := app.NewServer()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/vendors", nil)
	r.Header.Set("X-OpenTPRM-User", "attacker")
	r.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("dev headers in non-allow mode must not authorize writes/reads as analyst; got %d %s", w.Code, w.Body.String())
	}
}
