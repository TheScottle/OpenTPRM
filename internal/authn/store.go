package authn

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"
)

// SessionStore persists hashed sessions (SEC-AN-004).
type SessionStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Create inserts a new session. Returns the plaintext session ID and CSRF token once.
func (s *SessionStore) Create(ctx context.Context, userID string, aal int, roles []string, email string) (*Session, error) {
	id, idHash, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	csrf, csrfHash, err := NewCSRFToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &Session{
		ID:        id,
		IDHash:    idHash,
		UserID:    userID,
		CreatedAt: now,
		LastSeen:  now,
		Absolute:  now.Add(AbsoluteTimeout),
		AAL:       aal,
		CSRFToken: csrf,
		CSRFHash:  csrfHash,
		Roles:     append([]string(nil), roles...),
		Email:     email,
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, created_at, last_seen_at, absolute_expires_at, aal, csrf_hash, revoked, step_up_at)
		VALUES(?,?,?,?,?,?,?,0,'')`,
		idHash, userID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		sess.Absolute.Format(time.RFC3339Nano), aal, csrfHash)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// LookupByID resolves a plaintext cookie value to a live session.
func (s *SessionStore) LookupByID(ctx context.Context, id string) (*Session, error) {
	if id == "" {
		return nil, ErrInvalidSession
	}
	hash := HashToken(id)
	var (
		userID, created, lastSeen, absolute, csrfHash string
		aal, revoked                                  int
	)
	var stepUpAt string
	err := s.db.QueryRowContext(ctx, `SELECT user_id, created_at, last_seen_at, absolute_expires_at, aal, csrf_hash, revoked, COALESCE(step_up_at,'')
		FROM sessions WHERE id_hash=?`, hash).
		Scan(&userID, &created, &lastSeen, &absolute, &aal, &csrfHash, &revoked, &stepUpAt)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:       id,
		IDHash:   hash,
		UserID:   userID,
		AAL:      aal,
		CSRFHash: csrfHash,
		Revoked:  revoked == 1,
	}
	sess.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	sess.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
	sess.Absolute, _ = time.Parse(time.RFC3339Nano, absolute)
	if stepUpAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, stepUpAt); err == nil {
			sess.StepUpAt = t
		}
	}

	// Attach roles from users table when present.
	var rolesJSON string
	var email string
	_ = s.db.QueryRowContext(ctx, `SELECT roles_json, email FROM users WHERE id=?`, userID).Scan(&rolesJSON, &email)
	_ = json.Unmarshal([]byte(rolesJSON), &sess.Roles)
	sess.Email = email

	if err := sess.Alive(time.Now().UTC()); err != nil {
		return nil, err
	}
	return sess, nil
}

// Touch updates last_seen (idle timer).
func (s *SessionStore) Touch(ctx context.Context, idHash string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE id_hash=? AND revoked=0`, now, idHash)
	return err
}

// Rotate replaces the session ID at login / privilege change (SEC-AN-004).
func (s *SessionStore) Rotate(ctx context.Context, old *Session) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Revoke(ctx, old.IDHash); err != nil {
		return nil, err
	}
	return s.Create(ctx, old.UserID, old.AAL, old.Roles, old.Email)
}

// Revoke marks a session revoked (SEC-AN-005).
func (s *SessionStore) Revoke(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE id_hash=?`, idHash)
	return err
}

// RevokeAllForUser ends every session for a user (SEC-AN-005 / SEC-AN-007).
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RecordStepUp stamps WebAuthn step-up time on the session and persists AAL + step_up_at.
func (s *SessionStore) RecordStepUp(ctx context.Context, sess *Session) error {
	now := time.Now().UTC()
	sess.StepUpAt = now
	if sess.AAL < 3 {
		sess.AAL = 3
	}
	ts := now.Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET aal=?, last_seen_at=?, step_up_at=? WHERE id_hash=?`,
		sess.AAL, ts, ts, sess.IDHash)
	return err
}

// IssueCSRF rotates the synchronizer token for HTML form rendering (plaintext only returned here).
func (s *SessionStore) IssueCSRF(ctx context.Context, sess *Session) (string, error) {
	if sess == nil || sess.IDHash == "" {
		return "", ErrInvalidSession
	}
	token, hash, err := NewCSRFToken()
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET csrf_hash=? WHERE id_hash=? AND revoked=0`, hash, sess.IDHash); err != nil {
		return "", err
	}
	sess.CSRFToken = token
	sess.CSRFHash = hash
	return token, nil
}
