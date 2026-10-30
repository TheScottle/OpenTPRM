package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if a.Store == nil {
		writeProblem(w, 503, "unavailable", "store unavailable")
		return
	}
	if !a.authorize(w, ac, authz.ActionIdentityManage, authz.Resource{Type: "user", ID: "*"}) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		includeDisabled := r.URL.Query().Get("include_disabled") == "1"
		users, err := authn.ListUsers(r.Context(), a.Store.DB(), includeDisabled)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": users})
	case path == "" && r.Method == http.MethodPost:
		a.handleUserCreate(w, r, ac)
	case strings.HasSuffix(path, ":reset-password") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, ":reset-password")
		id = strings.TrimSuffix(id, "/")
		a.handleUserResetPassword(w, r, ac, id)
	case strings.HasSuffix(path, ":disable") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, ":disable")
		a.handleUserSetDisabled(w, r, ac, id, true)
	case strings.HasSuffix(path, ":enable") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, ":enable")
		a.handleUserSetDisabled(w, r, ac, id, false)
	case path != "" && r.Method == http.MethodGet:
		u, err := authn.GetUser(r.Context(), a.Store.DB(), path)
		if err != nil {
			writeProblem(w, 404, "not_found", "user not found")
			return
		}
		writeJSON(w, 200, u)
	case path != "" && (r.Method == http.MethodPatch || r.Method == http.MethodPut):
		a.handleUserPatch(w, r, ac, path)
	default:
		writeProblem(w, 404, "not_found", "unknown users path")
	}
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	var body struct {
		Email                  string   `json:"email"`
		DisplayName            string   `json:"display_name"`
		Roles                  []string `json:"roles"`
		Password               string   `json:"password"`
		MustChangePassword     bool     `json:"must_change_password"`
		SecondAdminEmail       string   `json:"second_admin_email"`
		SecondAdminPassword    string   `json:"second_admin_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	roles := body.Roles
	if authn.RolesTouchAdmin(nil, roles) {
		if err := authn.VerifySecondAdmin(r.Context(), a.Store.DB(), ac.PrincipalID, body.SecondAdminEmail, body.SecondAdminPassword, time.Now().UTC()); err != nil {
			writeProblem(w, 403, "sod", err.Error())
			return
		}
	}
	u, temp, err := authn.CreateUser(r.Context(), a.Store.DB(), authn.CreateUserInput{
		Email: body.Email, DisplayName: body.DisplayName, Roles: roles,
		Password: body.Password, MustChangePassword: body.MustChangePassword, ActorID: ac.PrincipalID,
	})
	if err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	a.auditIdentity(ac, "user.create", u.ID, `{"email":"`+u.Email+`"}`)
	out := map[string]any{"user": u}
	if temp != "" {
		out["temporary_password"] = temp
	}
	writeJSON(w, 201, out)
}

func (a *App) handleUserPatch(w http.ResponseWriter, r *http.Request, ac authz.Context, id string) {
	var body struct {
		DisplayName         *string   `json:"display_name"`
		Roles               *[]string `json:"roles"`
		Disabled            *bool     `json:"disabled"`
		SecondAdminEmail    string    `json:"second_admin_email"`
		SecondAdminPassword string    `json:"second_admin_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	if id == ac.PrincipalID && body.Roles != nil {
		writeProblem(w, 403, "sod", "cannot change own roles")
		return
	}
	before, err := authn.GetUser(r.Context(), a.Store.DB(), id)
	if err != nil {
		writeProblem(w, 404, "not_found", "user not found")
		return
	}
	afterRoles := before.Roles
	if body.Roles != nil {
		afterRoles = *body.Roles
	}
	if authn.RolesTouchAdmin(before.Roles, afterRoles) {
		if err := authn.VerifySecondAdmin(r.Context(), a.Store.DB(), ac.PrincipalID, body.SecondAdminEmail, body.SecondAdminPassword, time.Now().UTC()); err != nil {
			writeProblem(w, 403, "sod", err.Error())
			return
		}
	}
	u, err := authn.UpdateUser(r.Context(), a.Store.DB(), id, authn.UpdateUserPatch{
		DisplayName: body.DisplayName, Roles: body.Roles, Disabled: body.Disabled, ActorID: ac.PrincipalID,
	})
	if err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	if body.Disabled != nil && *body.Disabled && a.Sessions != nil {
		_, _ = a.Sessions.RevokeAllForUser(r.Context(), id)
	}
	a.auditIdentity(ac, "user.update", id, "")
	writeJSON(w, 200, u)
}

func (a *App) handleUserResetPassword(w http.ResponseWriter, r *http.Request, ac authz.Context, id string) {
	var body struct {
		Password            string `json:"password"`
		MustChangePassword  bool   `json:"must_change_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	u, err := authn.GetUser(r.Context(), a.Store.DB(), id)
	if err != nil {
		writeProblem(w, 404, "not_found", "user not found")
		return
	}
	temp := ""
	pass := body.Password
	if pass == "" {
		pass, err = authn.GenerateTempPassword()
		if err != nil {
			writeProblem(w, 500, "error", "password generate failed")
			return
		}
		temp = pass
		body.MustChangePassword = true
	}
	if err := authn.SetUserPassword(r.Context(), a.Store.DB(), id, pass, u.Email, ac.PrincipalID, body.MustChangePassword || temp != ""); err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	if a.Sessions != nil {
		_, _ = a.Sessions.RevokeAllForUser(r.Context(), id)
	}
	a.auditIdentity(ac, "user.reset_password", id, "")
	out := map[string]any{"ok": true, "user_id": id}
	if temp != "" {
		out["temporary_password"] = temp
	}
	writeJSON(w, 200, out)
}

func (a *App) handleUserSetDisabled(w http.ResponseWriter, r *http.Request, ac authz.Context, id string, disabled bool) {
	id = strings.TrimSuffix(id, "/")
	if id == ac.PrincipalID {
		writeProblem(w, 403, "sod", "cannot disable own account")
		return
	}
	dis := disabled
	u, err := authn.UpdateUser(r.Context(), a.Store.DB(), id, authn.UpdateUserPatch{
		Disabled: &dis, ActorID: ac.PrincipalID,
	})
	if err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	if disabled && a.Sessions != nil {
		_, _ = a.Sessions.RevokeAllForUser(r.Context(), id)
	}
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	a.auditIdentity(ac, action, id, "")
	writeJSON(w, 200, u)
}

func (a *App) auditIdentity(ac authz.Context, action, id, diff string) {
	if a.Audit == nil {
		return
	}
	_ = a.Audit.Append(rContext(ac), audit.Event{
		Actor: ac.PrincipalID, Action: action, ResourceType: "user", ResourceID: id,
		Decision: "allow", DiffRedacted: diff,
	})
}
