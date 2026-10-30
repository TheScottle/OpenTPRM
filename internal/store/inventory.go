package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func defaultsVendor(v *Vendor) {
	if v.Status == "" {
		v.Status = "prospect"
	}
	if v.Classification == "" {
		v.Classification = "Internal"
	}
	if v.AllowlistJSON == "" {
		v.AllowlistJSON = "[]"
	}
	if v.AliasesJSON == "" {
		v.AliasesJSON = "[]"
	}
	if v.DomainsJSON == "" {
		v.DomainsJSON = "[]"
	}
	if v.TagsJSON == "" {
		v.TagsJSON = "[]"
	}
	if v.PublicPrivate == "" {
		v.PublicPrivate = "private"
	}
}

// NormalizeVendorKey builds a duplicate-detection key (INV-002).
func NormalizeVendorKey(legalName, domain, lei string) string {
	name := strings.ToLower(strings.TrimSpace(legalName))
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	dom := strings.ToLower(strings.TrimSpace(domain))
	lei = strings.ToUpper(strings.TrimSpace(lei))
	return b.String() + "|" + dom + "|" + lei
}

func primaryDomain(domainsJSON string) string {
	var domains []string
	_ = json.Unmarshal([]byte(domainsJSON), &domains)
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}

func (s *Store) appendHistory(tx *sql.Tx, objectType, objectID, actor, beforeJSON, afterJSON, reason string) error {
	_, err := tx.Exec(`INSERT INTO object_history(id, object_type, object_id, actor, ts, before_json, after_json, reason)
		VALUES(?,?,?,?,?,?,?,?)`,
		uuid.Must(uuid.NewV7()).String(), objectType, objectID, actor, nowUTC(), beforeJSON, afterJSON, reason)
	return err
}

// CreateVendor inserts a third party (INV-001).
func (s *Store) CreateVendor(ctx context.Context, v Vendor) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	defaultsVendor(&v)
	if err := ValidateTagsJSON(v.TagsJSON); err != nil {
		return err
	}
	now := nowUTC()
	return s.WithWrite(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO third_parties(
			id, legal_name, aliases_json, lei, country, hq_address, domains_json,
			parent_id, ultimate_parent_id, public_private, regulated, status, tier, tags_json,
			created_at, created_by, updated_at, updated_by, classification, restricted, allowlist_json
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			v.ID, v.LegalName, v.AliasesJSON, v.LEI, v.Country, v.HQAddress, v.DomainsJSON,
			v.ParentID, v.UltimateParentID, v.PublicPrivate, boolInt(v.Regulated), v.Status, v.Tier, v.TagsJSON,
			now, v.CreatedBy, now, v.UpdatedBy, v.Classification, boolInt(v.Restricted), v.AllowlistJSON)
		if err != nil {
			return err
		}
		after, _ := json.Marshal(v)
		return s.appendHistory(tx, "third_party", v.ID, v.CreatedBy, "{}", string(after), "create")
	})
}

// GetVendor returns one vendor by id.
func (s *Store) GetVendor(ctx context.Context, id string) (Vendor, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Vendor{}, err
	}
	var v Vendor
	var regulated, restricted int
	err := s.db.QueryRowContext(ctx, `SELECT id, legal_name, aliases_json, lei, country, hq_address, domains_json,
		parent_id, ultimate_parent_id, public_private, regulated, status, tier, tags_json,
		classification, restricted, allowlist_json, created_by, updated_by, created_at, updated_at, row_version
		FROM third_parties WHERE id=?`, id).Scan(
		&v.ID, &v.LegalName, &v.AliasesJSON, &v.LEI, &v.Country, &v.HQAddress, &v.DomainsJSON,
		&v.ParentID, &v.UltimateParentID, &v.PublicPrivate, &regulated, &v.Status, &v.Tier, &v.TagsJSON,
		&v.Classification, &restricted, &v.AllowlistJSON, &v.CreatedBy, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt, &v.RowVersion)
	if err != nil {
		return Vendor{}, err
	}
	v.Regulated = regulated == 1
	v.Restricted = restricted == 1
	return v, nil
}

// ListVendors returns vendors (visibility predicates applied by caller/Cedar).
func (s *Store) ListVendors(ctx context.Context) ([]Vendor, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, legal_name, aliases_json, lei, country, hq_address, domains_json,
		parent_id, ultimate_parent_id, public_private, regulated, status, tier, tags_json,
		classification, restricted, allowlist_json, created_by, updated_by, created_at, updated_at, row_version
		FROM third_parties ORDER BY legal_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vendor
	for rows.Next() {
		var v Vendor
		var regulated, restricted int
		if err := rows.Scan(&v.ID, &v.LegalName, &v.AliasesJSON, &v.LEI, &v.Country, &v.HQAddress, &v.DomainsJSON,
			&v.ParentID, &v.UltimateParentID, &v.PublicPrivate, &regulated, &v.Status, &v.Tier, &v.TagsJSON,
			&v.Classification, &restricted, &v.AllowlistJSON, &v.CreatedBy, &v.UpdatedBy, &v.CreatedAt, &v.UpdatedAt, &v.RowVersion); err != nil {
			return nil, err
		}
		v.Regulated = regulated == 1
		v.Restricted = restricted == 1
		out = append(out, v)
	}
	return out, rows.Err()
}

// UpdateVendor updates INV-001 fields and appends history (INV-007).
func (s *Store) UpdateVendor(ctx context.Context, v Vendor, reason string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	defaultsVendor(&v)
	if err := ValidateTagsJSON(v.TagsJSON); err != nil {
		return err
	}
	before, err := s.GetVendor(ctx, v.ID)
	if err != nil {
		return err
	}
	now := nowUTC()
	return s.WithWrite(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE third_parties SET
			legal_name=?, aliases_json=?, lei=?, country=?, hq_address=?, domains_json=?,
			parent_id=?, ultimate_parent_id=?, public_private=?, regulated=?, status=?, tier=?, tags_json=?,
			updated_at=?, updated_by=?, classification=?, restricted=?, allowlist_json=?, row_version=row_version+1
			WHERE id=?`,
			v.LegalName, v.AliasesJSON, v.LEI, v.Country, v.HQAddress, v.DomainsJSON,
			v.ParentID, v.UltimateParentID, v.PublicPrivate, boolInt(v.Regulated), v.Status, v.Tier, v.TagsJSON,
			now, v.UpdatedBy, v.Classification, boolInt(v.Restricted), v.AllowlistJSON, v.ID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return sql.ErrNoRows
		}
		bj, _ := json.Marshal(before)
		aj, _ := json.Marshal(v)
		return s.appendHistory(tx, "third_party", v.ID, v.UpdatedBy, string(bj), string(aj), reason)
	})
}

// FindDuplicateVendors detects duplicates on normalized name + domain + LEI (INV-002).
func (s *Store) FindDuplicateVendors(ctx context.Context, legalName, domainsJSON, lei string) ([]Vendor, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	key := NormalizeVendorKey(legalName, primaryDomain(domainsJSON), lei)
	all, err := s.ListVendors(ctx)
	if err != nil {
		return nil, err
	}
	var out []Vendor
	for _, v := range all {
		if NormalizeVendorKey(v.LegalName, primaryDomain(v.DomainsJSON), v.LEI) == key {
			out = append(out, v)
		}
	}
	return out, nil
}

// MergeVendors merges source into target with audited history (INV-002).
func (s *Store) MergeVendors(ctx context.Context, targetID, sourceID, actor, reason string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	if targetID == sourceID {
		return fmt.Errorf("cannot merge vendor into itself")
	}
	target, err := s.GetVendor(ctx, targetID)
	if err != nil {
		return err
	}
	source, err := s.GetVendor(ctx, sourceID)
	if err != nil {
		return err
	}
	return s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE engagements SET third_party_id=? WHERE third_party_id=?`, targetID, sourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE vendor_contacts SET third_party_id=? WHERE third_party_id=?`, targetID, sourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE fourth_party_links SET from_third_party_id=? WHERE from_third_party_id=?`, targetID, sourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE fourth_party_links SET to_third_party_id=? WHERE to_third_party_id=?`, targetID, sourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE third_parties SET status='terminated', updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
			nowUTC(), actor, sourceID); err != nil {
			return err
		}
		before, _ := json.Marshal(map[string]any{"target": target, "source": source})
		after, _ := json.Marshal(map[string]any{"surviving_id": targetID, "merged_id": sourceID})
		return s.appendHistory(tx, "third_party", targetID, actor, string(before), string(after), reason)
	})
}

// ListHistory returns version history for an object (INV-007).
func (s *Store) ListHistory(ctx context.Context, objectType, objectID string) ([]HistoryEntry, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_type, object_id, actor, ts, before_json, after_json, reason
		FROM object_history WHERE object_type=? AND object_id=? ORDER BY ts DESC`, objectType, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		if err := rows.Scan(&h.ID, &h.ObjectType, &h.ObjectID, &h.Actor, &h.TS, &h.BeforeJSON, &h.AfterJSON, &h.Reason); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CreateEngagement inserts a full engagement (INV-003).
func (s *Store) CreateEngagement(ctx context.Context, e Engagement) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	if e.ContractRefsJSON == "" {
		e.ContractRefsJSON = "[]"
	}
	if e.DataTypesJSON == "" {
		e.DataTypesJSON = "[]"
	}
	if e.DataLocationsJSON == "" {
		e.DataLocationsJSON = "[]"
	}
	if e.AccessTypesJSON == "" {
		e.AccessTypesJSON = "[]"
	}
	if e.IntegrationMethodsJSON == "" {
		e.IntegrationMethodsJSON = "[]"
	}
	if e.HighestClassification == "" {
		e.HighestClassification = "Internal"
	}
	if e.VendorAIUse == "" {
		e.VendorAIUse = "unknown"
	}
	if e.Substitutability == 0 {
		e.Substitutability = 3
	}
	if e.OperationalCriticality == 0 {
		e.OperationalCriticality = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO engagements(
		id, third_party_id, service_description, service_category, relationship_owner, business_unit,
		client_ref, matter_ref, contract_refs_json, start_date, end_date, renewal_date, spend_band,
		data_types_json, highest_classification, data_volume_band, data_locations_json, access_types_json,
		integration_methods_json, operational_criticality, substitutability, vendor_ai_use, vendor_ai_description,
		subcontractor_use, inherent_tier, next_action_due, created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.ThirdPartyID, e.ServiceDescription, e.ServiceCategory, e.RelationshipOwner, e.BusinessUnit,
		e.ClientRef, e.MatterRef, e.ContractRefsJSON, e.StartDate, e.EndDate, e.RenewalDate, e.SpendBand,
		e.DataTypesJSON, e.HighestClassification, e.DataVolumeBand, e.DataLocationsJSON, e.AccessTypesJSON,
		e.IntegrationMethodsJSON, e.OperationalCriticality, e.Substitutability, e.VendorAIUse, e.VendorAIDescription,
		boolInt(e.SubcontractorUse), e.InherentTier, e.NextActionDue, now, e.CreatedBy, now, e.UpdatedBy)
	return err
}

// ListEngagementsByVendor lists engagements for a third party.
func (s *Store) ListEngagementsByVendor(ctx context.Context, vendorID string) ([]Engagement, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, third_party_id, service_description, service_category, relationship_owner,
		business_unit, client_ref, matter_ref, contract_refs_json, start_date, end_date, renewal_date, spend_band,
		data_types_json, highest_classification, data_volume_band, data_locations_json, access_types_json,
		integration_methods_json, operational_criticality, substitutability, vendor_ai_use, vendor_ai_description,
		subcontractor_use, inherent_tier, next_action_due, created_by, updated_by, created_at, updated_at, row_version
		FROM engagements WHERE third_party_id=? ORDER BY created_at`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Engagement
	for rows.Next() {
		var e Engagement
		var sub int
		if err := rows.Scan(&e.ID, &e.ThirdPartyID, &e.ServiceDescription, &e.ServiceCategory, &e.RelationshipOwner,
			&e.BusinessUnit, &e.ClientRef, &e.MatterRef, &e.ContractRefsJSON, &e.StartDate, &e.EndDate, &e.RenewalDate, &e.SpendBand,
			&e.DataTypesJSON, &e.HighestClassification, &e.DataVolumeBand, &e.DataLocationsJSON, &e.AccessTypesJSON,
			&e.IntegrationMethodsJSON, &e.OperationalCriticality, &e.Substitutability, &e.VendorAIUse, &e.VendorAIDescription,
			&sub, &e.InherentTier, &e.NextActionDue, &e.CreatedBy, &e.UpdatedBy, &e.CreatedAt, &e.UpdatedAt, &e.RowVersion); err != nil {
			return nil, err
		}
		e.SubcontractorUse = sub == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// ComputeNextActionDue sets next_action_due from the earliest of renewal / reassessment hints (INV-009).
func (s *Store) ComputeNextActionDue(ctx context.Context, engagementID, due string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE engagements SET next_action_due=?, updated_at=?, row_version=row_version+1 WHERE id=?`,
		due, nowUTC(), engagementID)
	return err
}

// CreateContact inserts a vendor contact (INV-004).
func (s *Store) CreateContact(ctx context.Context, c VendorContact) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO vendor_contacts(
		id, third_party_id, role, name, email, last_verified, created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.ThirdPartyID, c.Role, c.Name, c.Email, c.LastVerified, now, c.CreatedBy, now, c.UpdatedBy)
	return err
}

// ListContacts returns contacts for a vendor.
func (s *Store) ListContacts(ctx context.Context, vendorID string) ([]VendorContact, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, third_party_id, role, name, email, last_verified, created_by, updated_by, created_at, updated_at
		FROM vendor_contacts WHERE third_party_id=? ORDER BY role, name`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VendorContact
	for rows.Next() {
		var c VendorContact
		if err := rows.Scan(&c.ID, &c.ThirdPartyID, &c.Role, &c.Name, &c.Email, &c.LastVerified, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateFourthPartyLink inserts a fourth-party edge (INV-005).
func (s *Store) CreateFourthPartyLink(ctx context.Context, l FourthPartyLink) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	if l.Role == "" {
		l.Role = "subprocessor"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO fourth_party_links(
		id, from_third_party_id, to_third_party_id, role, source, data_access, created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.FromThirdPartyID, l.ToThirdPartyID, l.Role, l.Source, l.DataAccess, now, l.CreatedBy, now, l.UpdatedBy)
	return err
}

// ListFourthPartyLinks lists all links (optionally filtered by from vendor).
func (s *Store) ListFourthPartyLinks(ctx context.Context, fromVendorID string) ([]FourthPartyLink, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	q := `SELECT id, from_third_party_id, to_third_party_id, role, source, data_access, created_by, updated_by, created_at, updated_at FROM fourth_party_links`
	args := []any{}
	if fromVendorID != "" {
		q += ` WHERE from_third_party_id=?`
		args = append(args, fromVendorID)
	}
	q += ` ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FourthPartyLink
	for rows.Next() {
		var l FourthPartyLink
		if err := rows.Scan(&l.ID, &l.FromThirdPartyID, &l.ToThirdPartyID, &l.Role, &l.Source, &l.DataAccess, &l.CreatedBy, &l.UpdatedBy, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// FourthPartyConcentration counts vendors behind each fourth party (INV-005 / RSK-004).
func (s *Store) FourthPartyConcentration(ctx context.Context) (map[string]int, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT to_third_party_id, COUNT(DISTINCT from_third_party_id) FROM fourth_party_links GROUP BY to_third_party_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// CreateIntake inserts an intake row.
func (s *Store) CreateIntake(ctx context.Context, in Intake) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	if in.AnswersJSON == "" {
		in.AnswersJSON = "{}"
	}
	if in.FactorScoresJSON == "" {
		in.FactorScoresJSON = "{}"
	}
	if in.PlanJSON == "" {
		in.PlanJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO intakes(
		id, engagement_id, answers_json, factor_scores_json, weighted_score, tier, plan_json, status,
		created_at, created_by, updated_at, updated_by
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.ID, in.EngagementID, in.AnswersJSON, in.FactorScoresJSON, in.WeightedScore, in.Tier, in.PlanJSON, in.Status,
		now, in.CreatedBy, now, in.UpdatedBy)
	return err
}

func (s *Store) GetIntake(ctx context.Context, id string) (Intake, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Intake{}, err
	}
	var in Intake
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, answers_json, factor_scores_json, weighted_score, tier, plan_json, status, created_by, updated_by FROM intakes WHERE id=?`, id).
		Scan(&in.ID, &in.EngagementID, &in.AnswersJSON, &in.FactorScoresJSON, &in.WeightedScore, &in.Tier, &in.PlanJSON, &in.Status, &in.CreatedBy, &in.UpdatedBy)
	return in, err
}

func (s *Store) UpdateIntake(ctx context.Context, in Intake) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `UPDATE intakes SET answers_json=?, factor_scores_json=?, weighted_score=?, tier=?, plan_json=?, status=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
		in.AnswersJSON, in.FactorScoresJSON, in.WeightedScore, in.Tier, in.PlanJSON, in.Status, now, in.UpdatedBy, in.ID)
	return err
}

func (s *Store) CreateAssessment(ctx context.Context, as Assessment) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	if as.Type == "" {
		as.Type = "onboarding"
	}
	if as.PlanJSON == "" {
		as.PlanJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO assessments(id, engagement_id, type, state, plan_json, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?)`, as.ID, as.EngagementID, as.Type, as.State, as.PlanJSON, now, as.CreatedBy, now, as.UpdatedBy)
	return err
}

func (s *Store) GetAssessment(ctx context.Context, id string) (Assessment, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Assessment{}, err
	}
	var as Assessment
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, type, state, plan_json, created_by, updated_by FROM assessments WHERE id=?`, id).
		Scan(&as.ID, &as.EngagementID, &as.Type, &as.State, &as.PlanJSON, &as.CreatedBy, &as.UpdatedBy)
	return as, err
}

func (s *Store) ListAssessments(ctx context.Context) ([]Assessment, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, type, state, plan_json, created_by, updated_by FROM assessments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Assessment
	for rows.Next() {
		var as Assessment
		if err := rows.Scan(&as.ID, &as.EngagementID, &as.Type, &as.State, &as.PlanJSON, &as.CreatedBy, &as.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, as)
	}
	return out, rows.Err()
}

func (s *Store) TransitionAssessment(ctx context.Context, as Assessment, from, actor, reason string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	now := nowUTC()
	return s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE assessments SET state=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
			as.State, now, as.UpdatedBy, as.ID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO assessment_transitions(id, assessment_id, from_state, to_state, actor, reason, ts) VALUES(?,?,?,?,?,?,?)`,
			uuid.Must(uuid.NewV7()).String(), as.ID, from, as.State, actor, reason, now)
		return err
	})
}

func (s *Store) ListTemplates(ctx context.Context) ([]Template, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind FROM questionnaire_templates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListEvidence(ctx context.Context) ([]Evidence, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, status, evidence_type, classification, license_tag FROM evidence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.Status, &e.EvidenceType, &e.Classification, &e.LicenseTag); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context) ([]Finding, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, title, severity, status, finding_type FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Title, &f.Severity, &f.Status, &f.FindingType); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ShredVendor destroys vendor data keys and leaves a tombstone (AT-14 / ARC-003).
func (s *Store) ShredVendor(ctx context.Context, vendorID, actor, policy string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	if err := s.CanShredObject(ctx, "third_party", vendorID); err != nil {
		return err
	}
	now := nowUTC()
	return s.WithWrite(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM vendor_data_keys WHERE vendor_id=?`, vendorID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM evidence_pages WHERE evidence_id IN (SELECT id FROM evidence WHERE engagement_id IN (SELECT id FROM engagements WHERE third_party_id=?))`, vendorID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM evidence WHERE engagement_id IN (SELECT id FROM engagements WHERE third_party_id=?)`, vendorID); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO tombstones(id, object_type, object_id, shredded_at, policy) VALUES(?,?,?,?,?)`,
			uuid.Must(uuid.NewV7()).String(), "third_party", vendorID, now, policy)
		return err
	})
}
