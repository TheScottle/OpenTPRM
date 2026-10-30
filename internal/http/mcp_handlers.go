package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/gateway"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
)

func (a *App) ensureGateway() *gateway.Gateway {
	if a.GW != nil {
		return a.GW
	}
	reg := mcp.DefaultRegistry()
	a.GW = gateway.New(a.PDP, reg)
	return a.GW
}

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	gw := a.ensureGateway()
	s := &mcp.Server{
		Origins: []string{a.Cfg.Server.PublicBaseURL},
		ListFn:  gw.VisibleTools,
		CallFn: func(req *http.Request, agent, delegator authz.Context, tool string, args json.RawMessage) (json.RawMessage, int, string) {
			res := gw.Call(req.Context(), agent, delegator, tool, args)
			if !res.OK {
				return nil, res.Status, res.Error
			}
			return res.Result, 200, ""
		},
	}
	s.ServeHTTP(w, r)
}

func (a *App) handlePRM(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource": a.Cfg.Server.PublicBaseURL + "/mcp",
		"authorization_servers": []string{a.Cfg.Server.PublicBaseURL},
		"scopes_supported": []string{"tprm.read", "tprm.content.read", "tprm.suggest", "tprm.change.request", "tprm.restricted.read"},
		"bearer_methods_supported": []string{"header"},
		"resource_signing_alg_values_supported": []string{"ES256", "EdDSA"},
	})
}

func (a *App) handleASMeta(w http.ResponseWriter, r *http.Request) {
	base := a.Cfg.Server.PublicBaseURL
	writeJSON(w, 200, map[string]any{
		"issuer": base,
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint": base + "/oauth/token",
		"code_challenge_methods_supported": []string{"S256"},
		"dpop_signing_alg_values_supported": []string{"ES256", "EdDSA"},
		"grant_types_supported": []string{"authorization_code", "client_credentials", "refresh_token"},
	})
}
