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

func TestINV_API_VendorContactEngagementRoutes(t *testing.T) {
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 21)
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
	app := &httpserver.App{Keyring: kr, Store: st, PDP: pdp, AllowDevHeaders: true, SealedMode: false}
	srv := app.NewServer()

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
		srv.Handler.ServeHTTP(w, r)
		return w
	}

	w := do(http.MethodPost, "/api/v1/vendors", map[string]any{"legal_name": "API Co", "domains_json": `["api.example"]`})
	if w.Code != 201 {
		t.Fatalf("create vendor: %d %s", w.Code, w.Body.String())
	}
	var vendor map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &vendor)
	vid := vendor["id"].(string)

	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/contacts", map[string]any{
		"role": "security", "name": "Sam", "email": "sam@api.example",
	})
	if w.Code != 201 {
		t.Fatalf("contact: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodPost, "/api/v1/vendors/"+vid+"/engagements", map[string]any{
		"relationship_owner": "ro", "service_description": "Hosting",
	})
	if w.Code != 201 {
		t.Fatalf("engagement: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/vendors/"+vid+"/history", nil)
	if w.Code != 200 {
		t.Fatalf("history: %d %s", w.Code, w.Body.String())
	}
	w = do(http.MethodGet, "/api/v1/openapi.json", nil)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("fourth-party-links")) {
		t.Fatalf("openapi missing catalog: %d", w.Code)
	}
}
