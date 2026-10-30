package httpserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func (a *App) handleLoginUI(w http.ResponseWriter, r *http.Request) {
	a.ensureTemplates()
	if r.Method == http.MethodPost {
		// Form POST → password login then redirect.
		_ = r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")
		next := r.FormValue("next")
		if next == "" {
			next = r.URL.Query().Get("next")
		}
		if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		if a.Store == nil || a.Sessions == nil {
			writeProblem(w, 503, "unavailable", "auth unavailable")
			return
		}
		now := time.Now().UTC()
		u, hash, err := authn.GetUserByEmail(r.Context(), a.Store.DB(), email)
		if err != nil || authn.CheckLoginAllowed(u, now) != nil {
			data := map[string]any{"Title": "Sign in", "Error": "Invalid credentials", "Next": next}
			_ = a.Templates.ExecuteTemplate(w, "login.tmpl", data)
			return
		}
		ok, _ := authn.VerifyPassword(hash, password)
		if !ok {
			_ = authn.RecordLoginFailure(r.Context(), a.Store.DB(), u.ID, now)
			data := map[string]any{"Title": "Sign in", "Error": "Invalid credentials", "Next": next}
			_ = a.Templates.ExecuteTemplate(w, "login.tmpl", data)
			return
		}
		_ = authn.RecordLoginSuccess(r.Context(), a.Store.DB(), u.ID, now)
		sess, err := a.Sessions.Create(r.Context(), u.ID, 2, u.Roles, u.Email)
		if err != nil {
			writeProblem(w, 500, "error", "session create failed")
			return
		}
		authn.SetSessionCookie(w, sess.ID, r.TLS != nil)
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	next := r.URL.Query().Get("next")
	data := map[string]any{"Title": "Sign in", "Next": next}
	if err := a.Templates.ExecuteTemplate(w, "login.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleLogoutUI(w http.ResponseWriter, r *http.Request) {
	if a.Sessions != nil {
		if c, err := r.Cookie(authn.SessionCookie); err == nil && c.Value != "" {
			_ = a.Sessions.Revoke(r.Context(), authn.HashToken(c.Value))
		}
	}
	authn.ClearSessionCookie(w, r.TLS != nil)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleVendorsUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	if r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "vendor", ID: "*"}) {
			return
		}
		_ = r.ParseForm()
		action := r.FormValue("action")
		switch action {
		case "create":
			v := store.Vendor{
				ID: uuid.Must(uuid.NewV7()).String(), LegalName: strings.TrimSpace(r.FormValue("legal_name")),
				Status: "active", Classification: "Internal", CreatedBy: ac.PrincipalID, UpdatedBy: ac.PrincipalID,
				DomainsJSON: "[]", AliasesJSON: "[]", TagsJSON: "[]", AllowlistJSON: "[]",
			}
			if v.LegalName == "" {
				writeProblem(w, 400, "bad_request", "legal_name required")
				return
			}
			if err := a.Store.CreateVendor(ctx, v); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		case "update":
			id := r.FormValue("id")
			existing, err := a.Store.GetVendor(ctx, id)
			if err != nil {
				writeProblem(w, 404, "not_found", "vendor not found")
				return
			}
			if name := strings.TrimSpace(r.FormValue("legal_name")); name != "" {
				existing.LegalName = name
			}
			if st := strings.TrimSpace(r.FormValue("status")); st != "" {
				existing.Status = st
			}
			existing.UpdatedBy = ac.PrincipalID
			if err := a.Store.UpdateVendor(ctx, existing, "ui_update"); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		case "create_engagement":
			vid := r.FormValue("vendor_id")
			e := store.Engagement{
				ID: uuid.Must(uuid.NewV7()).String(), ThirdPartyID: vid,
				RelationshipOwner: r.FormValue("relationship_owner"),
				ServiceDescription: r.FormValue("service_description"),
				CreatedBy: ac.PrincipalID, UpdatedBy: ac.PrincipalID,
			}
			if e.RelationshipOwner == "" {
				e.RelationshipOwner = ac.PrincipalID
			}
			if err := a.Store.CreateEngagement(ctx, e); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		}
		http.Redirect(w, r, "/vendors", http.StatusSeeOther)
		return
	}
	var vendors []store.Vendor
	if a.Store != nil && ac.Authenticated() {
		if a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "vendor", ID: "*"}) {
			vendors, _ = a.Store.ListVendors(ctx)
		} else {
			return
		}
	}
	canWrite := ac.HasRole("risk_analyst") || ac.HasRole("tprm_program_manager") || ac.HasRole("relationship_owner")
	data := map[string]any{
		"Title": "Vendors", "User": ac.PrincipalID, "Roles": ac.Roles, "Vendors": vendors,
		"CanWrite": canWrite, "CSRFToken": a.csrfForRequest(r),
		"IsAdmin": ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "vendors.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleIntakeQueueUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	if r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionIntakeSubmit, authz.Resource{Type: "intake", ID: "*"}) {
			return
		}
		_ = r.ParseForm()
		action := r.FormValue("action")
		switch action {
		case "create":
			in := store.Intake{
				ID: uuid.Must(uuid.NewV7()).String(),
				EngagementID: strings.TrimSpace(r.FormValue("engagement_id")),
				AnswersJSON: "{}", FactorScoresJSON: "{}", PlanJSON: "{}",
				Status: "draft", CreatedBy: ac.PrincipalID, UpdatedBy: ac.PrincipalID,
			}
			if in.EngagementID == "" {
				writeProblem(w, 400, "bad_request", "engagement_id required")
				return
			}
			if err := a.Store.CreateIntake(ctx, in); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		case "submit":
			id := r.FormValue("id")
			in, err := a.Store.GetIntake(ctx, id)
			if err != nil {
				writeProblem(w, 404, "not_found", "intake not found")
				return
			}
			in.Status = "submitted"
			in.UpdatedBy = ac.PrincipalID
			if err := a.Store.UpdateIntake(ctx, in); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		}
		http.Redirect(w, r, "/intakes", http.StatusSeeOther)
		return
	}
	var items []store.Intake
	var engagements []store.Engagement
	if a.Store != nil && ac.Authenticated() {
		items, _ = a.Store.ListIntakes(ctx)
		vendors, _ := a.Store.ListVendors(ctx)
		for _, v := range vendors {
			eng, _ := a.Store.ListEngagementsByVendor(ctx, v.ID)
			engagements = append(engagements, eng...)
		}
	}
	canWrite := ac.HasRole("risk_analyst") || ac.HasRole("tprm_program_manager") || ac.HasRole("relationship_owner")
	data := map[string]any{
		"Title": "Intake queue", "User": ac.PrincipalID, "Roles": ac.Roles, "Items": items,
		"Engagements": engagements, "CanWrite": canWrite, "CSRFToken": a.csrfForRequest(r),
		"IsAdmin": ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "intakes.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleAdminUsersUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !a.authorize(w, ac, authz.ActionIdentityManage, authz.Resource{Type: "user", ID: "*"}) {
		return
	}
	ctx := r.Context()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		action := r.FormValue("action")
		switch action {
		case "create":
			roles := strings.FieldsFunc(r.FormValue("roles"), func(r rune) bool { return r == ',' || r == ' ' })
			if authn.RolesTouchAdmin(nil, roles) {
				if err := authn.VerifySecondAdmin(ctx, a.Store.DB(), ac.PrincipalID, r.FormValue("second_admin_email"), r.FormValue("second_admin_password"), time.Now().UTC()); err != nil {
					writeProblem(w, 403, "sod", err.Error())
					return
				}
			}
			_, _, err := authn.CreateUser(ctx, a.Store.DB(), authn.CreateUserInput{
				Email: r.FormValue("email"), DisplayName: r.FormValue("display_name"),
				Roles: roles, Password: r.FormValue("password"), MustChangePassword: r.FormValue("must_change") == "1",
				ActorID: ac.PrincipalID,
			})
			if err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
		case "disable", "enable":
			id := r.FormValue("id")
			if id == ac.PrincipalID {
				writeProblem(w, 403, "sod", "cannot disable own account")
				return
			}
			dis := action == "disable"
			_, err := authn.UpdateUser(ctx, a.Store.DB(), id, authn.UpdateUserPatch{Disabled: &dis, ActorID: ac.PrincipalID})
			if err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
			if dis && a.Sessions != nil {
				_, _ = a.Sessions.RevokeAllForUser(ctx, id)
			}
		case "reset_password":
			id := r.FormValue("id")
			u, err := authn.GetUser(ctx, a.Store.DB(), id)
			if err != nil {
				writeProblem(w, 404, "not_found", "user not found")
				return
			}
			pass := r.FormValue("password")
			if pass == "" {
				pass, err = authn.GenerateTempPassword()
				if err != nil {
					writeProblem(w, 500, "error", "generate failed")
					return
				}
			}
			if err := authn.SetUserPassword(ctx, a.Store.DB(), id, pass, u.Email, ac.PrincipalID, true); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
			if a.Sessions != nil {
				_, _ = a.Sessions.RevokeAllForUser(ctx, id)
			}
		}
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	users, _ := authn.ListUsers(ctx, a.Store.DB(), true)
	data := map[string]any{
		"Title": "Users", "User": ac.PrincipalID, "Roles": ac.Roles, "Users": users,
		"AssignableRoles": authn.AssignableRoles, "CSRFToken": a.csrfForRequest(r),
		"IsAdmin": true,
	}
	if err := a.Templates.ExecuteTemplate(w, "users.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}
