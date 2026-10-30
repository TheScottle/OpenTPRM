package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenAPI_RoutesHaveMuxRegistrationSmoke ensures every /api/v1 path in openapi.yaml
// is dispatched by the App mux (not "unknown API path"). Auth/method failures are OK.
func TestOpenAPI_RoutesHaveMuxRegistrationSmoke(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Paths) == 0 {
		t.Fatal("no openapi paths")
	}

	_, h := testApp(t)
	uuid := "00000000-0000-7000-8000-000000000001"
	paramRe := regexp.MustCompile(`\{[^}/]+\}`)

	for path := range doc.Paths {
		concrete := paramRe.ReplaceAllString(path, uuid)
		// Prefer a realistic report type for /reports/{type}.
		if strings.Contains(path, "/reports/{type}") {
			concrete = strings.ReplaceAll(concrete, uuid, "inventory")
		}
		if strings.Contains(path, "/pages/{page}") {
			concrete = regexp.MustCompile(`/pages/`+uuid).ReplaceAllString(concrete, "/pages/1")
		}
		full := "/api/v1" + concrete
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		registered := false
		var lastBody string
		var lastCode int
		for _, m := range methods {
			req := httptest.NewRequest(m, full, nil)
			req.Header.Set("X-OpenTPRM-User", "analyst1")
			req.Header.Set("X-OpenTPRM-Roles", "risk_analyst,approver,security_administrator")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			lastCode, lastBody = w.Code, w.Body.String()
			if strings.Contains(lastBody, "unknown API path") {
				continue
			}
			registered = true
			break
		}
		if !registered {
			t.Errorf("openapi path %s → %s not registered (last %d %s)", path, full, lastCode, lastBody)
		}
	}
}
