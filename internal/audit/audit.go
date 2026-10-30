package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/google/uuid"
)

// Event is an append-only audit record (SEC-LOG-001).
type Event struct {
	ID            string
	TS            time.Time
	Actor         string
	Delegator     string
	PrincipalType string
	Action        string
	ResourceType  string
	ResourceID    string
	Decision      string
	PolicyIDs     []string
	RequestID     string
	TraceID       string
	IP            string
	UserAgent     string
	DiffRedacted  string
	PrevHash      string
	Hash          string
}

// Logger writes hash-chained audit events.
type Logger struct {
	db      *sql.DB
	keyring *crypto.Keyring
}

func New(db *sql.DB, keyring *crypto.Keyring) *Logger {
	return &Logger{db: db, keyring: keyring}
}

// Append adds an event linked to the previous hash.
func (l *Logger) Append(ctx context.Context, e Event) error {
	if e.ID == "" {
		e.ID = uuid.Must(uuid.NewV7()).String()
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if ac, ok := authz.FromContext(ctx); ok {
		if e.Actor == "" {
			e.Actor = ac.PrincipalID
		}
		if e.Delegator == "" {
			e.Delegator = ac.DelegatorID
		}
		if e.PrincipalType == "" {
			e.PrincipalType = string(ac.PrincipalType)
		}
		if e.TraceID == "" {
			e.TraceID = ac.TraceID
		}
		if e.IP == "" {
			e.IP = ac.IP
		}
	}

	prev, err := l.latestHash(ctx)
	if err != nil {
		return err
	}
	e.PrevHash = prev
	e.Hash = HashEvent(e)

	policies, _ := json.Marshal(e.PolicyIDs)
	_, err = l.db.ExecContext(ctx, `INSERT INTO audit_events(
		id, ts, actor, delegator, principal_type, action, resource_type, resource_id,
		decision, policy_ids, request_id, trace_id, ip, user_agent, diff_redacted, prev_hash, hash
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TS.Format(time.RFC3339Nano), e.Actor, e.Delegator, e.PrincipalType, e.Action,
		e.ResourceType, e.ResourceID, e.Decision, string(policies), e.RequestID, e.TraceID,
		e.IP, e.UserAgent, e.DiffRedacted, e.PrevHash, e.Hash,
	)
	return err
}

func (l *Logger) latestHash(ctx context.Context) (string, error) {
	var h sql.NullString
	err := l.db.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY ts DESC, id DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return strings.Repeat("0", 64), nil
	}
	if err != nil {
		// empty table
		if strings.Contains(err.Error(), "no rows") {
			return strings.Repeat("0", 64), nil
		}
		// try again treating empty
		var count int
		_ = l.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_events`).Scan(&count)
		if count == 0 {
			return strings.Repeat("0", 64), nil
		}
		return "", err
	}
	if !h.Valid {
		return strings.Repeat("0", 64), nil
	}
	return h.String, nil
}

// HashEvent computes SHA-256(prev_hash || canonical event).
func HashEvent(e Event) string {
	policies, _ := json.Marshal(e.PolicyIDs)
	canonical := strings.Join([]string{
		e.PrevHash,
		e.TS.UTC().Format(time.RFC3339Nano),
		e.Actor,
		e.Delegator,
		e.PrincipalType,
		e.Action,
		e.ResourceType,
		e.ResourceID,
		e.Decision,
		string(policies),
		e.RequestID,
		e.TraceID,
		e.IP,
		e.UserAgent,
		e.DiffRedacted,
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// VerifyResult describes chain verification.
type VerifyResult struct {
	OK           bool
	Checked      int
	FailedAtID   string
	FailedReason string
}

// Verify walks the chain and reports tampering (AT-11).
func (l *Logger) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT id, ts, actor, delegator, principal_type, action, resource_type, resource_id,
		decision, policy_ids, request_id, trace_id, ip, user_agent, diff_redacted, prev_hash, hash
		FROM audit_events ORDER BY ts ASC, id ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	expectedPrev := strings.Repeat("0", 64)
	var res VerifyResult
	for rows.Next() {
		var e Event
		var ts string
		var policies string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Delegator, &e.PrincipalType, &e.Action, &e.ResourceType, &e.ResourceID,
			&e.Decision, &policies, &e.RequestID, &e.TraceID, &e.IP, &e.UserAgent, &e.DiffRedacted, &e.PrevHash, &e.Hash); err != nil {
			return res, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(policies), &e.PolicyIDs)
		res.Checked++
		if e.PrevHash != expectedPrev {
			res.FailedAtID = e.ID
			res.FailedReason = fmt.Sprintf("prev_hash mismatch: got %s want %s", e.PrevHash, expectedPrev)
			return res, nil
		}
		want := HashEvent(e)
		if want != e.Hash {
			res.FailedAtID = e.ID
			res.FailedReason = "hash mismatch (row tampered)"
			return res, nil
		}
		expectedPrev = e.Hash
	}
	res.OK = true
	return res, rows.Err()
}

// Checkpoint signs the latest hash (SEC-LOG-003).
func (l *Logger) Checkpoint(ctx context.Context) error {
	if l.keyring == nil || l.keyring.Sealed() {
		return crypto.ErrSealed
	}
	h, err := l.latestHash(ctx)
	if err != nil {
		return err
	}
	sig, err := l.keyring.SignEd25519([]byte(h))
	if err != nil {
		return err
	}
	id := uuid.Must(uuid.NewV7()).String()
	_, err = l.db.ExecContext(ctx, `INSERT INTO audit_checkpoints(id, ts, latest_hash, signature) VALUES(?,?,?,?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), h, sig)
	return err
}
