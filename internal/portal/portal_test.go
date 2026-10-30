package portal_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/portal"
)

func TestPortalDisabledByDefault(t *testing.T) {
	s := &portal.Server{Enabled: false}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
}

func TestRouteIsolation_InternalAPINotOnPortal(t *testing.T) {
	s := &portal.Server{Enabled: true}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/vendors", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("internal API must not be on portal listener: %d", rr.Code)
	}
}
