package httpserver

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func (a *App) handleVendors(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")

	// /vendors:import
	if path == "/vendors:import" && r.Method == http.MethodPost {
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "vendor", ID: "*"}) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		res, err := a.Store.BulkImportVendorsCSV(r.Context(), r.Body, ac.PrincipalID)
		if err != nil {
			writeProblem(w, 400, "bad_request", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"results": res})
		return
	}

	// /vendors/{id}:merge
	if strings.Contains(path, ":merge") && r.Method == http.MethodPost {
		id := extractID(r.URL.Path, "/api/v1/vendors/", ":merge")
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "vendor", ID: id}) {
			return
		}
		var body struct {
			SourceID string `json:"source_id"`
			Reason   string `json:"reason"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.SourceID == "" {
			writeProblem(w, 400, "bad_request", "source_id required")
			return
		}
		if err := a.Store.MergeVendors(r.Context(), id, body.SourceID, ac.PrincipalID, body.Reason); err != nil {
			writeProblem(w, 400, "bad_request", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"surviving_id": id, "merged_id": body.SourceID})
		return
	}

	// Nested: /vendors/{id}/contacts | /engagements | /history
	if strings.Contains(path, "/contacts") {
		a.handleVendorContacts(w, r, ac)
		return
	}
	if strings.Contains(path, "/engagements") {
		a.handleVendorEngagements(w, r, ac)
		return
	}
	if strings.HasSuffix(path, "/history") && r.Method == http.MethodGet {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/vendors/"), "/history")
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "vendor", ID: id}) {
			return
		}
		items, err := a.Store.ListHistory(r.Context(), "third_party", id)
		if err != nil {
			writeProblem(w, 500, "error", "history failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}

	// /vendors/{id}
	if strings.HasPrefix(path, "/vendors/") && path != "/vendors/" {
		id := strings.TrimPrefix(path, "/vendors/")
		if strings.Contains(id, "/") {
			writeProblem(w, 404, "not_found", "unknown vendor subpath")
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "vendor", ID: id}) {
				return
			}
			v, err := a.Store.GetVendor(r.Context(), id)
			if err != nil {
				writeProblem(w, 404, "not_found", "vendor not found")
				return
			}
			w.Header().Set("ETag", etagVersion(v.RowVersion))
			writeJSON(w, 200, v)
		case http.MethodPut, http.MethodPatch:
			if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "vendor", ID: id}) {
				return
			}
			var body store.Vendor
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeProblem(w, 400, "bad_request", "invalid json")
				return
			}
			body.ID = id
			body.UpdatedBy = ac.PrincipalID
			if err := a.Store.UpdateVendor(r.Context(), body, "api_update"); err != nil {
				writeProblem(w, 500, "error", "update failed")
				return
			}
			got, _ := a.Store.GetVendor(r.Context(), id)
			w.Header().Set("ETag", etagVersion(got.RowVersion))
			writeJSON(w, 200, got)
		default:
			writeProblem(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}

	res := authz.Resource{Type: "vendor", ID: "*"}
	action := authz.ActionVendorRead
	if r.Method != http.MethodGet {
		action = authz.ActionVendorWrite
	}
	if !a.authorize(w, ac, action, res) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := a.Store.ListVendors(r.Context())
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		var body store.Vendor
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateVendor(r.Context(), body); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleVendorContacts(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	// /api/v1/vendors/{id}/contacts
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/vendors/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeProblem(w, 404, "not_found", "not found")
		return
	}
	vendorID := parts[0]
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "vendor", ID: vendorID}) {
			return
		}
		items, err := a.Store.ListContacts(r.Context(), vendorID)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "vendor", ID: vendorID}) {
			return
		}
		var body store.VendorContact
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.ThirdPartyID = vendorID
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateContact(r.Context(), body); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleVendorEngagements(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/vendors/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		writeProblem(w, 404, "not_found", "not found")
		return
	}
	vendorID := parts[0]
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionEngagementRead, authz.Resource{Type: "engagement", ID: "*"}) {
			return
		}
		items, err := a.Store.ListEngagementsByVendor(r.Context(), vendorID)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionEngagementWrite, authz.Resource{Type: "engagement", ID: "*"}) {
			return
		}
		var body store.Engagement
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.ThirdPartyID = vendorID
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateEngagement(r.Context(), body); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func (a *App) handleFourthPartyLinks(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	switch r.Method {
	case http.MethodGet:
		if !a.authorize(w, ac, authz.ActionVendorRead, authz.Resource{Type: "fourth_party_link", ID: "*"}) {
			return
		}
		from := r.URL.Query().Get("from")
		items, err := a.Store.ListFourthPartyLinks(r.Context(), from)
		if err != nil {
			writeProblem(w, 500, "error", "list failed")
			return
		}
		conc, _ := a.Store.FourthPartyConcentration(r.Context())
		writeJSON(w, 200, map[string]any{"items": items, "concentration": conc})
	case http.MethodPost:
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "fourth_party_link", ID: "*"}) {
			return
		}
		var body store.FourthPartyLink
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
		body.ID = uuid.Must(uuid.NewV7()).String()
		body.CreatedBy = ac.PrincipalID
		body.UpdatedBy = ac.PrincipalID
		if err := a.Store.CreateFourthPartyLink(r.Context(), body); err != nil {
			writeProblem(w, 500, "error", "create failed")
			return
		}
		writeJSON(w, 201, body)
	default:
		writeProblem(w, 405, "method_not_allowed", "method not allowed")
	}
}

func etagVersion(v int64) string {
	if v <= 0 {
		v = 1
	}
	return `"` + strconv.FormatInt(v, 10) + `"`
}
