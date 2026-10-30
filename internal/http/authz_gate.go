package httpserver

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

// isPublicPath lists routes reachable without an authenticated principal.
func (a *App) isPublicPath(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/health/live", p == "/health/ready":
		return true
	case strings.HasPrefix(p, "/static/"):
		return true
	case p == "/login", p == "/login/":
		return true
	case p == "/logout", p == "/logout/":
		return true
	case p == "/bootstrap", p == "/bootstrap/":
		return a.bootstrapPending(r)
	case p == "/api/v1/auth/bootstrap":
		return true
	case p == "/api/v1/auth/password/login":
		return true
	case p == "/api/v1/auth/logout":
		return true
	case strings.HasPrefix(p, "/api/v1/auth/webauthn/login/"):
		return true
	case strings.HasPrefix(p, "/api/v1/auth/webauthn/step-up/"):
		return true
	case p == "/mcp", strings.HasPrefix(p, "/.well-known/"), strings.HasPrefix(p, "/oauth/"):
		return true
	default:
		return false
	}
}

func (a *App) bootstrapPending(r *http.Request) bool {
	if a.Store == nil {
		return false
	}
	ok, err := authn.BootstrapPending(r.Context(), a.Store.DB(), time.Now().UTC())
	return err == nil && ok
}

func (a *App) requireAuthOrPublic(w http.ResponseWriter, r *http.Request, ac authz.Context) bool {
	if a.isPublicPath(r) {
		return true
	}
	if ac.Authenticated() {
		return true
	}
	a.writeUnauthenticated(w, r)
	return false
}

func (a *App) writeUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if isAPIRequest(r) {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	next := r.URL.RequestURI()
	if next == "" || next == "/login" || strings.HasPrefix(next, "/login?") {
		next = "/"
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func isAPIRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") || strings.Contains(accept, "application/problem+json")
}
