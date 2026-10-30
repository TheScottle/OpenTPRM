package authn

import (
	"context"
	"database/sql"
	"os"
	"time"
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

// ConsumeBootstrapToken validates and marks the token used, then creates the first admins
// with Argon2id password hashes (SEC-AN-002).
func ConsumeBootstrapToken(ctx context.Context, db *sql.DB, plaintext, secEmail, sysEmail, secPass, sysPass string, now time.Time) (secID, sysID string, err error) {
	return ConsumeBootstrapTokenWithPasswords(ctx, db, plaintext, secEmail, sysEmail, secPass, sysPass, now)
}
