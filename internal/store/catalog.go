package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TheScottle/OpenTPRM/internal/ai"
	"github.com/google/uuid"
)

// ContractRecord is a contracts row.
type ContractRecord struct {
	ID                   string `json:"id"`
	EngagementID         string `json:"engagement_id"`
	Title                string `json:"title"`
	StartDate            string `json:"start_date,omitempty"`
	EndDate              string `json:"end_date,omitempty"`
	RenewalDate          string `json:"renewal_date,omitempty"`
	ClauseChecklistJSON  string `json:"clause_checklist_json,omitempty"`
	CreatedBy            string `json:"created_by"`
	UpdatedBy            string `json:"updated_by"`
	CreatedAt            string `json:"created_at,omitempty"`
	UpdatedAt            string `json:"updated_at,omitempty"`
	RowVersion           int64  `json:"row_version,omitempty"`
}

// MonitoringSignal is a monitoring_signals row.
type MonitoringSignal struct {
	ID           string `json:"id"`
	EngagementID string `json:"engagement_id,omitempty"`
	ThirdPartyID string `json:"third_party_id,omitempty"`
	Source       string `json:"source"`
	PayloadRef   string `json:"payload_ref,omitempty"`
	Disposition  string `json:"disposition"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
}

// Suggestion is an ai_suggestions row.
type Suggestion struct {
	ID            string `json:"id"`
	EngagementID  string `json:"engagement_id,omitempty"`
	Kind          string `json:"kind"`
	PayloadJSON   string `json:"payload_json"`
	CitationsJSON string `json:"citations_json,omitempty"`
	Status        string `json:"status"`
	AgentClientID string `json:"agent_client_id,omitempty"`
	DelegatorID   string `json:"delegator_id,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	Classification string `json:"classification,omitempty"`
}

// ChangeRequest is a change_requests row.
type ChangeRequest struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	PatchJSON     string `json:"patch_json"`
	PatchSHA256   string `json:"patch_sha256"`
	TargetETag    string `json:"target_etag,omitempty"`
	Rationale     string `json:"rationale,omitempty"`
	CitationsJSON string `json:"citations_json,omitempty"`
	Status        string `json:"status"`
	AgentClientID string `json:"agent_client_id,omitempty"`
	DelegatorID   string `json:"delegator_id,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

// AgentClient is an agent_clients row.
type AgentClient struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	OwnerUserID      string `json:"owner_user_id"`
	ClientType       string `json:"client_type"`
	Status           string `json:"status"`
	MaxClassification string `json:"max_classification"`
	CreatedBy        string `json:"created_by"`
	UpdatedBy        string `json:"updated_by"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// ModelEndpoint is a model_endpoints row.
type ModelEndpoint struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	BaseURL           string `json:"base_url"`
	APIStyle          string `json:"api_style"`
	ModelName         string `json:"model_name"`
	LocalFlag         bool   `json:"local_flag"`
	MaxClassification string `json:"max_classification"`
	Approved          bool   `json:"approved"`
	CreatedBy         string `json:"created_by"`
	CreatedAt         string `json:"created_at,omitempty"`
}

// ModelRecord is a models row.
type ModelRecord struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
	License  string `json:"license"`
	Approved bool   `json:"approved"`
	CreatedAt string `json:"created_at,omitempty"`
}

// CreateFinding inserts a finding.
func (s *Store) CreateFinding(ctx context.Context, f Finding, actor string) (Finding, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Finding{}, err
	}
	if f.EngagementID == "" || f.Title == "" {
		return Finding{}, fmt.Errorf("engagement_id and title required")
	}
	if f.ID == "" {
		f.ID = uuid.Must(uuid.NewV7()).String()
	}
	if f.Severity == "" {
		f.Severity = "medium"
	}
	if f.Status == "" {
		f.Status = "open"
	}
	if f.FindingType == "" {
		f.FindingType = "control_gap"
	}
	if actor == "" {
		actor = "system"
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO findings(id, engagement_id, title, description, severity, status, finding_type,
		controls_json, created_at, created_by, updated_at, updated_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.EngagementID, f.Title, "", f.Severity, f.Status, f.FindingType, "[]", now, actor, now, actor)
	return f, err
}

// CreateContract inserts a contract.
func (s *Store) CreateContract(ctx context.Context, c ContractRecord) (ContractRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ContractRecord{}, err
	}
	if c.EngagementID == "" {
		return ContractRecord{}, fmt.Errorf("engagement_id required")
	}
	if c.ID == "" {
		c.ID = uuid.Must(uuid.NewV7()).String()
	}
	if c.ClauseChecklistJSON == "" {
		c.ClauseChecklistJSON = "[]"
	}
	now := nowUTC()
	c.CreatedAt, c.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO contracts(id, engagement_id, title, start_date, end_date, renewal_date, clause_checklist_json,
		created_at, created_by, updated_at, updated_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.EngagementID, c.Title, c.StartDate, c.EndDate, c.RenewalDate, c.ClauseChecklistJSON,
		now, c.CreatedBy, now, c.UpdatedBy)
	return c, err
}

// ListContracts lists contracts.
func (s *Store) ListContracts(ctx context.Context) ([]ContractRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, title, start_date, end_date, renewal_date, clause_checklist_json,
		created_by, updated_by, created_at, updated_at, row_version FROM contracts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContractRecord
	for rows.Next() {
		var c ContractRecord
		if err := rows.Scan(&c.ID, &c.EngagementID, &c.Title, &c.StartDate, &c.EndDate, &c.RenewalDate, &c.ClauseChecklistJSON,
			&c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt, &c.RowVersion); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateMonitoringSignal inserts a signal.
func (s *Store) CreateMonitoringSignal(ctx context.Context, m MonitoringSignal) (MonitoringSignal, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return MonitoringSignal{}, err
	}
	if m.ID == "" {
		m.ID = uuid.Must(uuid.NewV7()).String()
	}
	if m.Source == "" {
		m.Source = "internal"
	}
	if m.Disposition == "" {
		m.Disposition = "new"
	}
	now := nowUTC()
	m.CreatedAt, m.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO monitoring_signals(id, engagement_id, third_party_id, source, payload_ref, disposition, created_at, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		m.ID, m.EngagementID, m.ThirdPartyID, m.Source, m.PayloadRef, m.Disposition, now, now, m.UpdatedBy)
	return m, err
}

// ListMonitoringSignals lists signals.
func (s *Store) ListMonitoringSignals(ctx context.Context) ([]MonitoringSignal, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, third_party_id, source, payload_ref, disposition, created_at, updated_at, updated_by
		FROM monitoring_signals ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonitoringSignal
	for rows.Next() {
		var m MonitoringSignal
		if err := rows.Scan(&m.ID, &m.EngagementID, &m.ThirdPartyID, &m.Source, &m.PayloadRef, &m.Disposition, &m.CreatedAt, &m.UpdatedAt, &m.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CreateSuggestion inserts an AI suggestion.
func (s *Store) CreateSuggestion(ctx context.Context, sug Suggestion) (Suggestion, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Suggestion{}, err
	}
	if sug.Kind == "" || sug.PayloadJSON == "" {
		return Suggestion{}, fmt.Errorf("kind and payload_json required")
	}
	if sug.ID == "" {
		sug.ID = uuid.Must(uuid.NewV7()).String()
	}
	if sug.Status == "" {
		sug.Status = "proposed"
	}
	if sug.CitationsJSON == "" {
		sug.CitationsJSON = "[]"
	}
	if sug.Classification == "" {
		sug.Classification = "Internal"
	}
	now := nowUTC()
	sug.CreatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO ai_suggestions(id, engagement_id, kind, payload_json, citations_json, status, agent_client_id, delegator_id, created_at, classification)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		sug.ID, sug.EngagementID, sug.Kind, sug.PayloadJSON, sug.CitationsJSON, sug.Status, sug.AgentClientID, sug.DelegatorID, now, sug.Classification)
	return sug, err
}

// ListSuggestions lists AI suggestions.
func (s *Store) ListSuggestions(ctx context.Context) ([]Suggestion, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, engagement_id, kind, payload_json, citations_json, status, agent_client_id, delegator_id, created_at, classification
		FROM ai_suggestions ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Suggestion
	for rows.Next() {
		var sug Suggestion
		if err := rows.Scan(&sug.ID, &sug.EngagementID, &sug.Kind, &sug.PayloadJSON, &sug.CitationsJSON, &sug.Status, &sug.AgentClientID, &sug.DelegatorID, &sug.CreatedAt, &sug.Classification); err != nil {
			return nil, err
		}
		out = append(out, sug)
	}
	return out, rows.Err()
}

// GetSuggestion loads one AI suggestion.
func (s *Store) GetSuggestion(ctx context.Context, id string) (Suggestion, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Suggestion{}, err
	}
	var sug Suggestion
	err := s.db.QueryRowContext(ctx, `SELECT id, engagement_id, kind, payload_json, citations_json, status, agent_client_id, delegator_id, created_at, classification
		FROM ai_suggestions WHERE id=?`, id).
		Scan(&sug.ID, &sug.EngagementID, &sug.Kind, &sug.PayloadJSON, &sug.CitationsJSON, &sug.Status, &sug.AgentClientID, &sug.DelegatorID, &sug.CreatedAt, &sug.Classification)
	return sug, err
}

// AcceptSuggestion verifies citations against source text then marks accepted (AI-064).
func (s *Store) AcceptSuggestion(ctx context.Context, id, sourceText, actor string) (Suggestion, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return Suggestion{}, err
	}
	sug, err := s.GetSuggestion(ctx, id)
	if err != nil {
		return Suggestion{}, err
	}
	var cites []ai.Citation
	if sug.CitationsJSON != "" && sug.CitationsJSON != "[]" {
		if err := json.Unmarshal([]byte(sug.CitationsJSON), &cites); err != nil {
			return Suggestion{}, fmt.Errorf("citations_json: %w", err)
		}
	}
	if err := ai.PrepareAccept(sug.Status, cites, sourceText); err != nil {
		return Suggestion{}, err
	}
	now := nowUTC()
	_, err = s.db.ExecContext(ctx, `UPDATE ai_suggestions SET status=?, accepted_by=?, accepted_at=? WHERE id=?`,
		"accepted", actor, now, id)
	if err != nil {
		return Suggestion{}, err
	}
	sug.Status = "accepted"
	return sug, nil
}

// CreateChangeRequest inserts a change request.
func (s *Store) CreateChangeRequest(ctx context.Context, cr ChangeRequest) (ChangeRequest, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ChangeRequest{}, err
	}
	if cr.Action == "" || cr.TargetType == "" || cr.TargetID == "" || cr.PatchJSON == "" {
		return ChangeRequest{}, fmt.Errorf("action, target, and patch_json required")
	}
	if cr.ID == "" {
		cr.ID = uuid.Must(uuid.NewV7()).String()
	}
	if cr.Status == "" {
		cr.Status = "pending_approval"
	}
	if cr.CitationsJSON == "" {
		cr.CitationsJSON = "[]"
	}
	now := nowUTC()
	cr.CreatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO change_requests(id, action, target_type, target_id, patch_json, patch_sha256, target_etag, rationale, citations_json, status, agent_client_id, delegator_id, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		cr.ID, cr.Action, cr.TargetType, cr.TargetID, cr.PatchJSON, cr.PatchSHA256, cr.TargetETag, cr.Rationale, cr.CitationsJSON, cr.Status, cr.AgentClientID, cr.DelegatorID, now)
	return cr, err
}

// ListChangeRequests lists change requests.
func (s *Store) ListChangeRequests(ctx context.Context) ([]ChangeRequest, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, action, target_type, target_id, patch_json, patch_sha256, target_etag, rationale, citations_json, status, agent_client_id, delegator_id, created_at
		FROM change_requests ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeRequest
	for rows.Next() {
		var cr ChangeRequest
		if err := rows.Scan(&cr.ID, &cr.Action, &cr.TargetType, &cr.TargetID, &cr.PatchJSON, &cr.PatchSHA256, &cr.TargetETag, &cr.Rationale, &cr.CitationsJSON, &cr.Status, &cr.AgentClientID, &cr.DelegatorID, &cr.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

// GetChangeRequest loads one change request.
func (s *Store) GetChangeRequest(ctx context.Context, id string) (ChangeRequest, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ChangeRequest{}, err
	}
	var cr ChangeRequest
	err := s.db.QueryRowContext(ctx, `SELECT id, action, target_type, target_id, patch_json, patch_sha256, target_etag, rationale, citations_json, status, agent_client_id, delegator_id, created_at
		FROM change_requests WHERE id=?`, id).
		Scan(&cr.ID, &cr.Action, &cr.TargetType, &cr.TargetID, &cr.PatchJSON, &cr.PatchSHA256, &cr.TargetETag, &cr.Rationale, &cr.CitationsJSON, &cr.Status, &cr.AgentClientID, &cr.DelegatorID, &cr.CreatedAt)
	return cr, err
}

// ErrStaleChangeRequest is AT-06: target changed under a pending CR.
var ErrStaleChangeRequest = errors.New("change request stale: target ETag mismatch")

// DecideChangeRequest approves or rejects a pending change request (humans only; SOD vs requester).
// When the CR has a TargetETag, currentETag must match (AT-06). Dual-control: actor ≠ delegator.
func (s *Store) DecideChangeRequest(ctx context.Context, id, decision, actor, currentETag string) (ChangeRequest, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ChangeRequest{}, err
	}
	cr, err := s.GetChangeRequest(ctx, id)
	if err != nil {
		return ChangeRequest{}, err
	}
	if cr.Status != "pending_approval" {
		return ChangeRequest{}, fmt.Errorf("change request not pending")
	}
	if cr.DelegatorID != "" && cr.DelegatorID == actor {
		return ChangeRequest{}, fmt.Errorf("SOD: requester cannot decide own change request")
	}
	if cr.AgentClientID != "" && cr.AgentClientID == actor {
		return ChangeRequest{}, fmt.Errorf("SOD: agent client cannot decide change request")
	}
	if cr.TargetETag != "" && currentETag != cr.TargetETag {
		return ChangeRequest{}, ErrStaleChangeRequest
	}
	switch decision {
	case "approved", "rejected":
	default:
		return ChangeRequest{}, fmt.Errorf("decision must be approved or rejected")
	}
	now := nowUTC()
	_, err = s.db.ExecContext(ctx, `UPDATE change_requests SET status=?, decided_by=?, decided_at=? WHERE id=?`,
		decision, actor, now, id)
	if err != nil {
		return ChangeRequest{}, err
	}
	cr.Status = decision
	return cr, nil
}

// CreateAgentClient inserts an agent client.
func (s *Store) CreateAgentClient(ctx context.Context, c AgentClient) (AgentClient, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return AgentClient{}, err
	}
	if c.Name == "" || c.OwnerUserID == "" {
		return AgentClient{}, fmt.Errorf("name and owner_user_id required")
	}
	if c.ID == "" {
		c.ID = uuid.Must(uuid.NewV7()).String()
	}
	if c.ClientType == "" {
		c.ClientType = "delegated"
	}
	if c.Status == "" {
		c.Status = "active"
	}
	if c.MaxClassification == "" {
		c.MaxClassification = "Confidential"
	}
	now := nowUTC()
	c.CreatedAt, c.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_clients(id, name, owner_user_id, client_type, max_classification, status, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, c.OwnerUserID, c.ClientType, c.MaxClassification, c.Status, now, c.CreatedBy, now, c.UpdatedBy)
	return c, err
}

// ListAgentClients lists agent clients.
func (s *Store) ListAgentClients(ctx context.Context) ([]AgentClient, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, owner_user_id, client_type, status, max_classification, created_by, updated_by, created_at, updated_at
		FROM agent_clients ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentClient
	for rows.Next() {
		var c AgentClient
		if err := rows.Scan(&c.ID, &c.Name, &c.OwnerUserID, &c.ClientType, &c.Status, &c.MaxClassification, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateModelEndpoint inserts a model endpoint.
func (s *Store) CreateModelEndpoint(ctx context.Context, m ModelEndpoint) (ModelEndpoint, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ModelEndpoint{}, err
	}
	if m.Name == "" || m.BaseURL == "" || m.ModelName == "" {
		return ModelEndpoint{}, fmt.Errorf("name, base_url, model_name required")
	}
	if m.ID == "" {
		m.ID = uuid.Must(uuid.NewV7()).String()
	}
	if m.APIStyle == "" {
		m.APIStyle = "openai"
	}
	if m.MaxClassification == "" {
		m.MaxClassification = "Internal"
	}
	now := nowUTC()
	m.CreatedAt = now
	local := 0
	if m.LocalFlag {
		local = 1
	}
	approved := 0
	if m.Approved {
		approved = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO model_endpoints(id, name, base_url, api_style, model_name, local_flag, max_classification, created_at, created_by, approved)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		m.ID, m.Name, m.BaseURL, m.APIStyle, m.ModelName, local, m.MaxClassification, now, m.CreatedBy, approved)
	return m, err
}

// ListModelEndpoints lists model endpoints.
func (s *Store) ListModelEndpoints(ctx context.Context) ([]ModelEndpoint, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, base_url, api_style, model_name, local_flag, max_classification, approved, created_by, created_at
		FROM model_endpoints ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelEndpoint
	for rows.Next() {
		var m ModelEndpoint
		var local, approved int
		if err := rows.Scan(&m.ID, &m.Name, &m.BaseURL, &m.APIStyle, &m.ModelName, &local, &m.MaxClassification, &approved, &m.CreatedBy, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.LocalFlag = local != 0
		m.Approved = approved != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetModelEndpoint loads one model endpoint.
func (s *Store) GetModelEndpoint(ctx context.Context, id string) (ModelEndpoint, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ModelEndpoint{}, err
	}
	var m ModelEndpoint
	var local, approved int
	err := s.db.QueryRowContext(ctx, `SELECT id, name, base_url, api_style, model_name, local_flag, max_classification, approved, created_by, created_at
		FROM model_endpoints WHERE id=?`, id).
		Scan(&m.ID, &m.Name, &m.BaseURL, &m.APIStyle, &m.ModelName, &local, &m.MaxClassification, &approved, &m.CreatedBy, &m.CreatedAt)
	if err != nil {
		return ModelEndpoint{}, err
	}
	m.LocalFlag = local != 0
	m.Approved = approved != 0
	return m, nil
}

// UpdateModelEndpoint updates mutable fields on a model endpoint.
func (s *Store) UpdateModelEndpoint(ctx context.Context, m ModelEndpoint) (ModelEndpoint, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ModelEndpoint{}, err
	}
	if m.ID == "" {
		return ModelEndpoint{}, fmt.Errorf("id required")
	}
	cur, err := s.GetModelEndpoint(ctx, m.ID)
	if err != nil {
		return ModelEndpoint{}, err
	}
	if m.Name != "" {
		cur.Name = m.Name
	}
	if m.BaseURL != "" {
		cur.BaseURL = m.BaseURL
	}
	if m.APIStyle != "" {
		cur.APIStyle = m.APIStyle
	}
	if m.ModelName != "" {
		cur.ModelName = m.ModelName
	}
	if m.MaxClassification != "" {
		cur.MaxClassification = m.MaxClassification
	}
	cur.LocalFlag = m.LocalFlag
	cur.Approved = m.Approved
	local, approved := 0, 0
	if cur.LocalFlag {
		local = 1
	}
	if cur.Approved {
		approved = 1
	}
	_, err = s.db.ExecContext(ctx, `UPDATE model_endpoints SET name=?, base_url=?, api_style=?, model_name=?, local_flag=?, max_classification=?, approved=? WHERE id=?`,
		cur.Name, cur.BaseURL, cur.APIStyle, cur.ModelName, local, cur.MaxClassification, approved, cur.ID)
	return cur, err
}

// DeleteModelEndpoint removes a model endpoint registry row.
func (s *Store) DeleteModelEndpoint(ctx context.Context, id string) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM model_endpoints WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("model endpoint not found")
	}
	return nil
}

// CreateModel inserts a model registry row.
func (s *Store) CreateModel(ctx context.Context, m ModelRecord) (ModelRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return ModelRecord{}, err
	}
	if m.Name == "" || m.Version == "" || m.Digest == "" || m.License == "" {
		return ModelRecord{}, fmt.Errorf("name, version, digest, license required")
	}
	if m.ID == "" {
		m.ID = uuid.Must(uuid.NewV7()).String()
	}
	now := nowUTC()
	m.CreatedAt = now
	approved := 0
	if m.Approved {
		approved = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO models(id, name, version, digest, license, approved, created_at) VALUES(?,?,?,?,?,?,?)`,
		m.ID, m.Name, m.Version, m.Digest, m.License, approved, now)
	return m, err
}

// ListModels lists registered models.
func (s *Store) ListModels(ctx context.Context) ([]ModelRecord, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, version, digest, license, approved, created_at FROM models ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModelRecord
	for rows.Next() {
		var m ModelRecord
		var approved int
		if err := rows.Scan(&m.ID, &m.Name, &m.Version, &m.Digest, &m.License, &approved, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.Approved = approved != 0
		out = append(out, m)
	}
	return out, rows.Err()
}
