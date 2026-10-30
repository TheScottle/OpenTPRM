package authn

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
)

const BootstrapTTL = time.Hour

// RegisterBootstrapToken hashes and stores a one-time bootstrap token (OPS-003).
func RegisterBootstrapToken(ctx context.Context, db *sql.DB, plaintext string, now time.Time) error {
	hash := HashToken(plaintext)
	_, err := db.ExecContext(ctx, `INSERT INTO bootstrap_tokens(id_hash, created_at, expires_at, used) VALUES(?,?,?,0)`,
		hash, now.UTC().Format(time.RFC3339Nano), now.UTC().Add(BootstrapTTL).Format(time.RFC3339Nano))
	return err
}

// LoadBootstrapTokenFile reads a 0400 bootstrap token file and registers it.
func LoadBootstrapTokenFile(ctx context.Context, db *sql.DB, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return RegisterBootstrapToken(ctx, db, string(b), time.Now())
}

// ConsumeBootstrapToken validates and marks the token used, then creates the first admins.
// Returns the security + system administrator user IDs.
func ConsumeBootstrapToken(ctx context.Context, db *sql.DB, plaintext, secEmail, sysEmail string, now time.Time) (secID, sysID string, err error) {
	hash := HashToken(plaintext)
	var expires string
	var used int
	err = db.QueryRowContext(ctx, `SELECT expires_at, used FROM bootstrap_tokens WHERE id_hash=?`, hash).
		Scan(&expires, &used)
	if err == sql.ErrNoRows {
		return "", "", ErrBootstrapUsed
	}
	if err != nil {
		return "", "", err
	}
	if used != 0 {
		return "", "", ErrBootstrapUsed
	}
	exp, _ := time.Parse(time.RFC3339Nano, expires)
	if now.After(exp) {
		return "", "", ErrBootstrapUsed
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`UPDATE bootstrap_tokens SET used=1 WHERE id_hash=?`, hash); err != nil {
		return "", "", err
	}

	secID = uuid.Must(uuid.NewV7()).String()
	sysID = uuid.Must(uuid.NewV7()).String()
	ts := now.UTC().Format(time.RFC3339Nano)
	secRoles, _ := json.Marshal([]string{"security_administrator"})
	sysRoles, _ := json.Marshal([]string{"system_administrator"})

	if _, err := tx.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,0,?,?,?,?)`,
		secID, "workforce", secEmail, "Security Administrator", string(secRoles), ts, "bootstrap", ts, "bootstrap"); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES(?,?,?,?,?,0,?,?,?,?)`,
		sysID, "workforce", sysEmail, "System Administrator", string(sysRoles), ts, "bootstrap", ts, "bootstrap"); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return secID, sysID, nil
}
