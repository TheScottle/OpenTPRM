package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// AICallLog is an ai_call_logs row (AI labels / logging).
type AICallLog struct {
	ID           string `json:"id"`
	EndpointID   string `json:"endpoint_id"`
	ModelDigest  string `json:"model_digest"`
	TemplateHash string `json:"template_hash"`
	InputHash    string `json:"input_hash"`
	OutputHash   string `json:"output_hash"`
	Tokens       int    `json:"tokens"`
	LatencyMs    int    `json:"latency_ms"`
	Principal    string `json:"principal"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// InsertAICallLog writes one AI call log row (hashes only; sealed blobs optional later).
func (s *Store) InsertAICallLog(ctx context.Context, log AICallLog) (AICallLog, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return AICallLog{}, err
	}
	if log.EndpointID == "" || log.InputHash == "" || log.OutputHash == "" {
		return AICallLog{}, fmt.Errorf("endpoint_id, input_hash, and output_hash required")
	}
	if log.ID == "" {
		log.ID = uuid.Must(uuid.NewV7()).String()
	}
	if log.Principal == "" {
		log.Principal = "system"
	}
	now := nowUTC()
	log.CreatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO ai_call_logs(
		id, endpoint_id, model_digest, template_hash, input_hash, output_hash, tokens, latency_ms, principal, created_at
	) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		log.ID, log.EndpointID, log.ModelDigest, log.TemplateHash, log.InputHash, log.OutputHash,
		log.Tokens, log.LatencyMs, log.Principal, now)
	return log, err
}

// ListAICallLogs returns recent AI call logs (newest first).
func (s *Store) ListAICallLogs(ctx context.Context, limit int) ([]AICallLog, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, endpoint_id, model_digest, template_hash, input_hash, output_hash,
		tokens, latency_ms, principal, created_at FROM ai_call_logs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AICallLog
	for rows.Next() {
		var log AICallLog
		if err := rows.Scan(&log.ID, &log.EndpointID, &log.ModelDigest, &log.TemplateHash, &log.InputHash, &log.OutputHash,
			&log.Tokens, &log.LatencyMs, &log.Principal, &log.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, rows.Err()
}
