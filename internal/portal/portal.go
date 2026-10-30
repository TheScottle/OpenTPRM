package portal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/TheScottle/OpenTPRM/internal/store"
)

// QuestionnaireLister lists vendor-scoped questionnaire instances (optional).
type QuestionnaireLister interface {
	ListQuestionnaireInstancesByVendor(ctx context.Context, vendorID string) ([]store.QuestionnaireInstance, error)
}

// Server is Listener B — vendor portal (disabled by default).
type Server struct {
	Enabled     bool
	MagicLinks  *MagicLinkStore
	Store       QuestionnaireLister
	// VendorSessions maps session tokens to vendor IDs (stub).
	sessions map[string]string
}

// NewServer constructs a portal server; magic-link store is created when nil.
func NewServer(enabled bool) *Server {
	return &Server{
		Enabled:    enabled,
		MagicLinks: NewMagicLinkStore(0),
		sessions:   map[string]string{},
	}
}

func (s *Server) Handler() http.Handler {
	if s.MagicLinks == nil {
		s.MagicLinks = NewMagicLinkStore(0)
	}
	if s.sessions == nil {
		s.sessions = map[string]string{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.wrap(s.handleHome))
	mux.HandleFunc("/portal/", s.wrap(s.handlePortal))
	mux.HandleFunc("/portal/login", s.wrap(s.handleLogin))
	mux.HandleFunc("/portal/magic", s.wrap(s.handleMagicConsume))
	mux.HandleFunc("/portal/questionnaires", s.wrap(s.handleQuestionnaires))
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Portal login</h1>
<form method="POST" action="/portal/login">
<label>Vendor ID <input name="vendor_id" required></label>
<label>Email <input name="email" type="email" required></label>
<button type="submit">Send magic link</button>
</form></body></html>`))
	case http.MethodPost:
		_ = r.ParseForm()
		vendorID := strings.TrimSpace(r.FormValue("vendor_id"))
		email := strings.TrimSpace(r.FormValue("email"))
		tok, err := s.MagicLinks.Issue(vendorID, email)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		// Stub: return token in JSON for tests; production would email it.
		writeJSON(w, 200, map[string]any{
			"status": "magic_link_issued",
			"token":  tok,
			"hint":   "consume via GET /portal/magic?token=...",
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleMagicConsume(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	ml, err := s.MagicLinks.Consume(tok)
	if err != nil {
		status := http.StatusUnauthorized
		if err == ErrMagicLinkUsed {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	sess := hashMagic(tok + ":sess")[:32]
	s.sessions[sess] = ml.VendorID
	http.SetCookie(w, &http.Cookie{Name: "otp_portal", Value: sess, Path: "/portal", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]any{"vendor_id": ml.VendorID, "email": ml.Email, "session": true})
}

func (s *Server) vendorFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-OpenTPRM-Vendor"); v != "" {
		return v
	}
	if c, err := r.Cookie("otp_portal"); err == nil {
		return s.sessions[c.Value]
	}
	return ""
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/login") {
		s.handleLogin(w, r)
		return
	}
	vendorID := s.vendorFromRequest(r)
	if vendorID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, 200, map[string]any{"vendor_id": vendorID, "capabilities": []string{"questionnaire", "evidence_upload"}})
}

func (s *Server) handleQuestionnaires(w http.ResponseWriter, r *http.Request) {
	vendorID := s.vendorFromRequest(r)
	if vendorID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.Store == nil {
		writeJSON(w, 200, map[string]any{"vendor_id": vendorID, "items": []any{}})
		return
	}
	items, err := s.Store.ListQuestionnaireInstancesByVendor(r.Context(), vendorID)
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]any{"vendor_id": vendorID, "items": items})
}

// refuseInternalAPI ensures internal workforce routes are not served on Listener B.
func (s *Server) refuseInternalAPI(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
