package portal

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Server is Listener B — vendor portal (disabled by default).
type Server struct {
	Enabled bool
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.wrap(s.handleHome))
	mux.HandleFunc("/portal/", s.wrap(s.handlePortal))
	mux.HandleFunc("/api/v1/", s.wrap(s.refuseInternalAPI))
	return mux
}

func (s *Server) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Enabled {
			http.Error(w, "portal disabled", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
		next(w, r)
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>OpenTPRM Vendor Portal</h1>
<p>Privacy notice: business contact data only. Anti-automation controls apply.</p>
<a href="/portal/login">Login</a></body></html>`))
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	// Vendor namespace isolation: path must include vendor id claim from session (stub).
	vendorID := r.Header.Get("X-OpenTPRM-Vendor")
	if vendorID == "" && !strings.HasSuffix(r.URL.Path, "/login") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"vendor_id": vendorID, "capabilities": []string{"questionnaire", "evidence_upload"}})
}

// refuseInternalAPI ensures internal workforce routes are not served on Listener B.
func (s *Server) refuseInternalAPI(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}
