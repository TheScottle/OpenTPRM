package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/migrations"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	_ "github.com/ncruces/go-sqlite3/vfs/xts"
)

// Store is the sole data-access layer. Only this package opens the database.
type Store struct {
	db      *sql.DB
	keyring *crypto.Keyring
	writeMu sync.Mutex
	path    string
}

// Open opens an XTS-encrypted SQLite database. Key is applied via PRAGMA hexkey, never in DSN.
func Open(dataDir string, keyring *crypto.Keyring) (*Store, error) {
	if keyring == nil || keyring.Sealed() {
		return nil, crypto.ErrSealed
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dataDir, "opentprm.db")
	// Use xts VFS; do not put key in URI (ADR-003 / SEC).
	dsn := fmt.Sprintf("file:%s?vfs=xts&_pragma=busy_timeout(5000)", filepath.ToSlash(dbPath))

	hexKey, err := keyring.DBHexKey()
	if err != nil {
		return nil, err
	}
	if len(hexKey) != 128 || !isHex(hexKey) {
		return nil, fmt.Errorf("invalid db key material")
	}
	// Apply hexkey + session pragmas on every pooled connection (never via DSN).
	// A one-shot Exec after Open only keys the first connection; concurrent Ping
	// would otherwise open unkeyed pool conns and break later writes.
	initConn := func(conn *sqlite3.Conn) error {
		if err := conn.Exec(`PRAGMA hexkey='` + hexKey + `'`); err != nil {
			return fmt.Errorf("pragma hexkey: %w", err)
		}
		for _, p := range []string{
			`PRAGMA secure_delete=ON`,
			`PRAGMA foreign_keys=ON`,
			`PRAGMA temp_store=MEMORY`,
			`PRAGMA journal_mode=WAL`,
		} {
			if err := conn.Exec(p); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
		return nil
	}
	db, err := driver.Open(dsn, initConn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite + XTS: single writer; keep the pool at one conn.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db, keyring: keyring, path: dbPath}
	if err := s.Migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB exposes the pool for packages in store only (tests).
func (s *Store) DB() *sql.DB { return s.db }

// RequireAuthz refuses calls without a valid authorization context.
func RequireAuthz(ctx context.Context) (authz.Context, error) {
	ac, ok := authz.FromContext(ctx)
	if !ok || !ac.Valid() {
		return authz.Context{}, fmt.Errorf("store: missing authorization context")
	}
	return ac, nil
}

// Migrate applies embedded forward-only SQL migrations.
func (s *Store) Migrate() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for i, name := range names {
		version := i + 1
		var exists int
		err := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version=?`, version).Scan(&exists)
		if err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// WithWrite runs fn under the single-writer lock.
func (s *Store) WithWrite(fn func(tx *sql.Tx) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
