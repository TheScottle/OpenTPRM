package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/domain/contract"
	"github.com/TheScottle/OpenTPRM/internal/domain/finding"
	"github.com/TheScottle/OpenTPRM/internal/domain/monitoring"
	"github.com/TheScottle/OpenTPRM/internal/domain/offboarding"
	"github.com/TheScottle/OpenTPRM/internal/domain/risk"
	"github.com/google/uuid"
)

// RemediationPlan is a remediation_plans row (FND-004).
type RemediationPlan struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
	StepsJSON string `json:"steps_json"`
	Owner     string `json:"owner,omitempty"`
	DueDate   string `json:"due_date,omitempty"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// RiskResult is a risk_results / register entry (RSK-001/003).
type RiskResult struct {
	ID             string `json:"id"`
	EngagementID   string `json:"engagement_id"`
	AssessmentID   string `json:"assessment_id,omitempty"`
	FormulaVersion string `json:"formula_version"`
	InputsJSON     string `json:"inputs_json"`
	Magnitude      int    `json:"magnitude"`
	Likelihood     int    `json:"likelihood"`
	Residual       int    `json:"residual"`
	ResidualBand   string `json:"residual_band"`
	Explanation    string `json:"explanation"`
	CreatedAt      string `json:"created_at,omitempty"`
	CreatedBy      string `json:"created_by"`
}

// Obligation is an obligations row (CON-003).
type Obligation struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	ClientID     string `json:"client_id,omitempty"`
	Description  string `json:"description"`
	Source       string `json:"source,omitempty"`
	Status       string `json:"status"`
	DueDate      string `json:"due_date,omitempty"`
	CreatedBy    string `json:"created_by"`
	UpdatedBy    string `json:"updated_by"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	RowVersion   int64  `json:"row_version,omitempty"`
}

// ClientRecord is a clients row.
type ClientRecord struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	CreatedBy      string `json:"created_by"`
	UpdatedBy      string `json:"updated_by"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	Classification string `json:"classification,omitempty"`
}

// ClientRequirement is a client_requirements row (CON-004).
type ClientRequirement struct {
	ID                 string `json:"id"`
	ClientID           string `json:"client_id"`
	Text               string `json:"text"`
	FlowedToEngagement string `json:"flowed_to_engagement,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
	CreatedBy          string `json:"created_by"`
}

// OffboardingChecklist is an offboarding_checklists row (OFF-001).
type OffboardingChecklist struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id"`
	ItemsJSON    string `json:"items_json"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
}

// GetFinding loads one finding.
func (s *Store) GetFinding(ctx context.Context, id string) (Finding, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Finding{}, err
	}
	var f Finding
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, title, severity, status, finding_type FROM findings WHERE id=?`, id).
		Scan(&f.ID, &f.EngagementID, &f.Title, &f.Severity, &f.Status, &f.FindingType)
	return f, err
}

// TransitionFinding applies FND-002 status transitions.
func (s *Store) TransitionFinding(ctx context.Context, id, toStatus, actor, closureEvidenceID string) (Finding, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Finding{}, err
	}
	f, err := s.GetFinding(ctx, id)
	if err != nil {
		return Finding{}, err
	}
	from := finding.Status(f.Status)
	to := finding.Status(toStatus)
	if err := finding.CanTransition(from, to); err != nil {
		return Finding{}, err
	}
	if finding.RequiresClosureEvidence(to) && closureEvidenceID == "" {
		return Finding{}, fmt.Errorf("FND-005: closure requires validation evidence")
	}
	now := nowUTC()
	_, err = s.db.ExecContext(ctx, `UPDATE findings SET status=?, updated_at=?, updated_by=?, row_version=row_version+1 WHERE id=?`,
		toStatus, now, actor, id)
	if err != nil {
		return Finding{}, err
	}
	f.Status = toStatus
	return f, nil
}

// UpsertRemediationPlan creates or replaces a remediation plan (FND-004).
func (s *Store) UpsertRemediationPlan(ctx context.Context, p RemediationPlan) (RemediationPlan, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return RemediationPlan{}, err
	}
	if p.FindingID == "" {
		return RemediationPlan{}, fmt.Errorf("finding_id required")
	}
	if p.StepsJSON == "" {
		p.StepsJSON = "[]"
	}
	if p.Status == "" {
		p.Status = "open"
	}
	p.UpdatedAt = nowUTC()
	var existing string
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM remediation_plans WHERE finding_id=?`, p.FindingID).Scan(&existing)
	if existing != "" {
		p.ID = existing
		_, err := s.db.ExecContext(ctx, `UPDATE remediation_plans SET steps_json=?, owner=?, due_date=?, status=?, updated_at=? WHERE id=?`,
			p.StepsJSON, p.Owner, p.DueDate, p.Status, p.UpdatedAt, p.ID)
		return p, err
	}
	if p.ID == "" {
		p.ID = uuid.Must(uuid.NewV7()).String()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO remediation_plans(id, finding_id, steps_json, owner, due_date, status, updated_at) VALUES(?,?,?,?,?,?,?)`,
		p.ID, p.FindingID, p.StepsJSON, p.Owner, p.DueDate, p.Status, p.UpdatedAt)
	return p, err
}

// GetRemediationPlan loads the plan for a finding.
func (s *Store) GetRemediationPlan(ctx context.Context, findingID string) (RemediationPlan, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return RemediationPlan{}, err
	}
	var p RemediationPlan
	err := s.db.QueryRowContext(ctx, `SELECT id, finding_id, steps_json, owner, due_date, status, updated_at FROM remediation_plans WHERE finding_id=?`, findingID).
		Scan(&p.ID, &p.FindingID, &p.StepsJSON, &p.Owner, &p.DueDate, &p.Status, &p.UpdatedAt)
	return p, err
}

// PersistRiskResult stores a computed residual risk on the register (RSK-001/003).
func (s *Store) PersistRiskResult(ctx context.Context, engagementID, assessmentID, actor string, in risk.Input) (RiskResult, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return RiskResult{}, err
	}
	if engagementID == "" {
		return RiskResult{}, fmt.Errorf("engagement_id required")
	}
	res := risk.Compute(in)
	inJSON, _ := json.Marshal(in)
	rr := RiskResult{
		ID: uuid.Must(uuid.NewV7()).String(), EngagementID: engagementID, AssessmentID: assessmentID,
		FormulaVersion: res.FormulaVersion, InputsJSON: string(inJSON),
		Magnitude: res.Magnitude, Likelihood: res.Likelihood, Residual: res.Residual,
		ResidualBand: res.Band, Explanation: res.Explanation, CreatedAt: nowUTC(), CreatedBy: actor,
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO risk_results(id, engagement_id, assessment_id, formula_version, inputs_json, magnitude, likelihood, residual, residual_band, explanation, created_at, created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		rr.ID, rr.EngagementID, rr.AssessmentID, rr.FormulaVersion, rr.InputsJSON, rr.Magnitude, rr.Likelihood, rr.Residual, rr.ResidualBand, rr.Explanation, rr.CreatedAt, rr.CreatedBy)
	return rr, err
}

// ListRiskResults returns the risk register (newest first).
func (s *Store) ListRiskResults(ctx context.Context, engagementID string) ([]RiskResult, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	q := `SELECT id, engagement_id, assessment_id, formula_version, inputs_json, magnitude, likelihood, residual, residual_band, explanation, created_at, created_by FROM risk_results`
	var rows *sql.Rows
	var err error
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx, q+` WHERE engagement_id=? ORDER BY created_at DESC`, engagementID)
	} else {
		rows, err = s.db.QueryContext(ctx, q+` ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RiskResult
	for rows.Next() {
		var rr RiskResult
		if err := rows.Scan(&rr.ID, &rr.EngagementID, &rr.AssessmentID, &rr.FormulaVersion, &rr.InputsJSON, &rr.Magnitude, &rr.Likelihood, &rr.Residual, &rr.ResidualBand, &rr.Explanation, &rr.CreatedAt, &rr.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, rows.Err()
}

// CreateClient inserts a client.
func (s *Store) CreateClient(ctx context.Context, c ClientRecord) (ClientRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ClientRecord{}, err
	}
	if c.Name == "" {
		return ClientRecord{}, fmt.Errorf("name required")
	}
	if c.ID == "" {
		c.ID = uuid.Must(uuid.NewV7()).String()
	}
	if c.Classification == "" {
		c.Classification = "Client-Confidential"
	}
	now := nowUTC()
	c.CreatedAt, c.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients(id, name, created_at, created_by, updated_at, updated_by, classification) VALUES(?,?,?,?,?,?,?)`,
		c.ID, c.Name, now, c.CreatedBy, now, c.UpdatedBy, c.Classification)
	return c, err
}

// CreateClientRequirement inserts a client OCG requirement.
func (s *Store) CreateClientRequirement(ctx context.Context, req ClientRequirement) (ClientRequirement, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ClientRequirement{}, err
	}
	if req.ClientID == "" || req.Text == "" {
		return ClientRequirement{}, fmt.Errorf("client_id and text required")
	}
	if req.ID == "" {
		req.ID = uuid.Must(uuid.NewV7()).String()
	}
	req.CreatedAt = nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_requirements(id, client_id, text, flowed_to_engagement, created_at, created_by) VALUES(?,?,?,?,?,?)`,
		req.ID, req.ClientID, req.Text, req.FlowedToEngagement, req.CreatedAt, req.CreatedBy)
	return req, err
}

// FlowDownRequirement creates an obligation on an engagement from a client requirement (CON-004).
func (s *Store) FlowDownRequirement(ctx context.Context, requirementID, engagementID, actor string) (Obligation, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Obligation{}, err
	}
	var clientID, text string
	err := s.db.QueryRowContext(ctx, `SELECT client_id, text FROM client_requirements WHERE id=?`, requirementID).Scan(&clientID, &text)
	if err != nil {
		return Obligation{}, err
	}
	fd := contract.FlowDown{
		ClientID: clientID, RequirementID: requirementID, EngagementID: engagementID,
		Description: text, Source: "client_ocg",
	}
	if err := fd.Validate(); err != nil {
		return Obligation{}, err
	}
	ob, err := s.CreateObligation(ctx, Obligation{
		EngagementID: engagementID, ClientID: clientID, Description: text,
		Source: "client_ocg", Status: "open", CreatedBy: actor, UpdatedBy: actor,
	})
	if err != nil {
		return Obligation{}, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE client_requirements SET flowed_to_engagement=? WHERE id=?`, engagementID, requirementID)
	return ob, err
}

// CreateObligation inserts an obligation (CON-003).
func (s *Store) CreateObligation(ctx context.Context, o Obligation) (Obligation, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Obligation{}, err
	}
	if o.EngagementID == "" || o.Description == "" {
		return Obligation{}, fmt.Errorf("engagement_id and description required")
	}
	if o.ID == "" {
		o.ID = uuid.Must(uuid.NewV7()).String()
	}
	if o.Status == "" {
		o.Status = "open"
	}
	now := nowUTC()
	o.CreatedAt, o.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO obligations(id, engagement_id, client_id, description, source, status, due_date, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		o.ID, o.EngagementID, o.ClientID, o.Description, o.Source, o.Status, o.DueDate, now, o.CreatedBy, now, o.UpdatedBy)
	return o, err
}

// ListObligations lists obligations, optionally filtered by engagement.
func (s *Store) ListObligations(ctx context.Context, engagementID string) ([]Obligation, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	q := `SELECT id, engagement_id, client_id, description, source, status, due_date, created_by, updated_by, created_at, updated_at, row_version FROM obligations`
	var rows *sql.Rows
	var err error
	if engagementID != "" {
		rows, err = s.db.QueryContext(ctx, q+` WHERE engagement_id=? ORDER BY created_at`, engagementID)
	} else {
		rows, err = s.db.QueryContext(ctx, q+` ORDER BY created_at`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Obligation
	for rows.Next() {
		var o Obligation
		if err := rows.Scan(&o.ID, &o.EngagementID, &o.ClientID, &o.Description, &o.Source, &o.Status, &o.DueDate, &o.CreatedBy, &o.UpdatedBy, &o.CreatedAt, &o.UpdatedAt, &o.RowVersion); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetMonitoringDisposition records an analyst disposition (MON-005).
func (s *Store) SetMonitoringDisposition(ctx context.Context, signalID, disposition, actor string) (MonitoringSignal, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return MonitoringSignal{}, err
	}
	to := monitoring.Disposition(disposition)
	if err := monitoring.CanSet(monitoring.New, to); err != nil {
		return MonitoringSignal{}, err
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `UPDATE monitoring_signals SET disposition=?, updated_at=?, updated_by=? WHERE id=?`,
		disposition, now, actor, signalID)
	if err != nil {
		return MonitoringSignal{}, err
	}
	var m MonitoringSignal
	err = s.db.QueryRowContext(ctx, `SELECT id, engagement_id, third_party_id, source, payload_ref, disposition, created_at, updated_at, updated_by FROM monitoring_signals WHERE id=?`, signalID).
		Scan(&m.ID, &m.EngagementID, &m.ThirdPartyID, &m.Source, &m.PayloadRef, &m.Disposition, &m.CreatedAt, &m.UpdatedAt, &m.UpdatedBy)
	return m, err
}

// CreateOffboardingChecklist seeds OFF-001 items for an engagement.
func (s *Store) CreateOffboardingChecklist(ctx context.Context, engagementID, actor string) (OffboardingChecklist, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return OffboardingChecklist{}, err
	}
	if engagementID == "" {
		return OffboardingChecklist{}, fmt.Errorf("engagement_id required")
	}
	itemsJSON, err := offboarding.ItemsJSON(nil)
	if err != nil {
		return OffboardingChecklist{}, err
	}
	now := nowUTC()
	c := OffboardingChecklist{
		ID: uuid.Must(uuid.NewV7()).String(), EngagementID: engagementID,
		ItemsJSON: itemsJSON, Status: "open", CreatedAt: now, UpdatedAt: now, UpdatedBy: actor,
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO offboarding_checklists(id, engagement_id, items_json, status, created_at, updated_at, updated_by) VALUES(?,?,?,?,?,?,?)`,
		c.ID, c.EngagementID, c.ItemsJSON, c.Status, c.CreatedAt, c.UpdatedAt, c.UpdatedBy)
	return c, err
}

// GetOffboardingChecklist loads by engagement.
func (s *Store) GetOffboardingChecklist(ctx context.Context, engagementID string) (OffboardingChecklist, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return OffboardingChecklist{}, err
	}
	var c OffboardingChecklist
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, items_json, status, created_at, updated_at, updated_by FROM offboarding_checklists WHERE engagement_id=?`, engagementID).
		Scan(&c.ID, &c.EngagementID, &c.ItemsJSON, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.UpdatedBy)
	return c, err
}

// MarkOffboardingItem updates one checklist item.
func (s *Store) MarkOffboardingItem(ctx context.Context, engagementID, itemID, actor string, done bool, evidenceRef string) (OffboardingChecklist, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return OffboardingChecklist{}, err
	}
	c, err := s.GetOffboardingChecklist(ctx, engagementID)
	if err != nil {
		return OffboardingChecklist{}, err
	}
	items, err := offboarding.ParseItems(c.ItemsJSON)
	if err != nil {
		return OffboardingChecklist{}, err
	}
	updated, ok := offboarding.MarkDone(items, itemID, done, evidenceRef)
	if !ok {
		return OffboardingChecklist{}, fmt.Errorf("unknown checklist item %q", itemID)
	}
	raw, err := offboarding.ItemsJSON(updated)
	if err != nil {
		return OffboardingChecklist{}, err
	}
	status := "open"
	if offboarding.AllDone(updated) {
		status = "complete"
	}
	now := nowUTC()
	_, err = s.db.ExecContext(ctx, `UPDATE offboarding_checklists SET items_json=?, status=?, updated_at=?, updated_by=? WHERE id=?`,
		raw, status, now, actor, c.ID)
	if err != nil {
		return OffboardingChecklist{}, err
	}
	c.ItemsJSON, c.Status, c.UpdatedAt, c.UpdatedBy = raw, status, now, actor
	return c, nil
}

// ApplyDefaultContractClauses fills empty clause checklists with CON-002 defaults.
func (s *Store) ApplyDefaultContractClauses(ctx context.Context, contractID string) (ContractRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ContractRecord{}, err
	}
	raw, err := contract.ClausesJSON(contract.DefaultTier1Clauses())
	if err != nil {
		return ContractRecord{}, err
	}
	now := nowUTC()
	_, err = s.db.ExecContext(ctx, `UPDATE contracts SET clause_checklist_json=?, updated_at=?, row_version=row_version+1 WHERE id=? AND (clause_checklist_json='' OR clause_checklist_json='[]')`,
		raw, now, contractID)
	if err != nil {
		return ContractRecord{}, err
	}
	var c ContractRecord
	err = s.db.QueryRowContext(ctx, `SELECT id, engagement_id, title, start_date, end_date, renewal_date, clause_checklist_json, created_by, updated_by, created_at, updated_at, row_version FROM contracts WHERE id=?`, contractID).
		Scan(&c.ID, &c.EngagementID, &c.Title, &c.StartDate, &c.EndDate, &c.RenewalDate, &c.ClauseChecklistJSON, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt, &c.RowVersion)
	return c, err
}

// Ensure finding CreateFinding sets due_date from SLA when empty — helper used by tests.
func FindingDueDate(severity string, from time.Time) string {
	days := finding.DefaultSLADays(severity)
	return from.UTC().AddDate(0, 0, days).Format(time.RFC3339)
}
