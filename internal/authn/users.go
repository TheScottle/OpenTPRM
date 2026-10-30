package authn

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// User is a workforce identity row.
type User struct {
	ID                   string   `json:"id"`
	PrincipalType        string   `json:"principal_type"`
	Email                string   `json:"email"`
	DisplayName          string   `json:"display_name"`
	Roles                []string `json:"roles"`
	Disabled             bool     `json:"disabled"`
	MustChangePassword   bool     `json:"must_change_password"`
	FailedLoginCount     int      `json:"failed_login_count,omitempty"`
	LockedUntil          string   `json:"locked_until,omitempty"`
	LastLoginAt          string   `json:"last_login_at,omitempty"`
	PasswordChangedAt    string   `json:"password_changed_at,omitempty"`
	CreatedAt            string   `json:"created_at,omitempty"`
	CreatedBy            string   `json:"created_by,omitempty"`
	UpdatedAt            string   `json:"updated_at,omitempty"`
	UpdatedBy            string   `json:"updated_by,omitempty"`
	HasPassword          bool     `json:"has_password"`
}

// AdminRoles that trigger SOD-3 second-admin confirmation when granted/revoked.
var AdminRoles = map[string]bool{
	"security_administrator": true,
	"system_administrator":   true,
}

// AssignableRoles are workforce roles admins may grant.
var AssignableRoles = []string{
	"security_administrator", "system_administrator", "risk_analyst",
	"tprm_program_manager", "approver", "auditor", "viewer", "relationship_owner",
}

func isAssignableRole(role string) bool {
	for _, r := range AssignableRoles {
		if r == role {
			return true
		}
	}
	return false
}

// BootstrapPending reports whether an unused, unexpired bootstrap token remains.
func BootstrapPending(ctx context.Context, db *sql.DB, now time.Time) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM bootstrap_tokens WHERE used=0 AND expires_at > ?`,
		now.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n > 0, err
}

// ConsumeBootstrapTokenWithPasswords creates the first admins with Argon2id password hashes.
func ConsumeBootstrapTokenWithPasswords(ctx context.Context, db *sql.DB, plaintext, secEmail, sysEmail, secPass, sysPass string, now time.Time) (secID, sysID string, err error) {
	if err := ValidatePasswordPolicy(secPass, secEmail); err != nil {
		return "", "", err
	}
	if err := ValidatePasswordPolicy(sysPass, sysEmail); err != nil {
		return "", "", err
	}
	secHash, err := HashPassword(secPass)
	if err != nil {
		return "", "", err
	}
	sysHash, err := HashPassword(sysPass)
	if err != nil {
		return "", "", err
	}

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

	if _, err := tx.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by,
		password_hash, password_changed_at, must_change_password, failed_login_count, locked_until, last_login_at)
		VALUES(?,?,?,?,?,0,?,?,?,?,?,?,0,0,'','')`,
		secID, "workforce", secEmail, "Security Administrator", string(secRoles), ts, "bootstrap", ts, "bootstrap",
		secHash, ts); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by,
		password_hash, password_changed_at, must_change_password, failed_login_count, locked_until, last_login_at)
		VALUES(?,?,?,?,?,0,?,?,?,?,?,?,0,0,'','')`,
		sysID, "workforce", sysEmail, "System Administrator", string(sysRoles), ts, "bootstrap", ts, "bootstrap",
		sysHash, ts); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return secID, sysID, nil
}

// ListUsers returns workforce users (optionally including disabled).
func ListUsers(ctx context.Context, db *sql.DB, includeDisabled bool) ([]User, error) {
	q := `SELECT id, principal_type, email, display_name, roles_json, disabled,
		must_change_password, failed_login_count, locked_until, last_login_at, password_changed_at,
		created_at, created_by, updated_at, updated_by, password_hash
		FROM users WHERE principal_type='workforce'`
	if !includeDisabled {
		q += ` AND disabled=0`
	}
	q += ` ORDER BY email`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUser loads one user by id.
func GetUser(ctx context.Context, db *sql.DB, id string) (User, error) {
	u, _, err := GetUserPasswordHash(ctx, db, id)
	return u, err
}

// GetUserByEmail loads one user by email (case-insensitive) and returns the password hash.
func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (User, string, error) {
	row := db.QueryRowContext(ctx, `SELECT id, principal_type, email, display_name, roles_json, disabled,
		must_change_password, failed_login_count, locked_until, last_login_at, password_changed_at,
		created_at, created_by, updated_at, updated_by, password_hash
		FROM users WHERE lower(email)=lower(?)`, email)
	return scanUserWithHash(row)
}

// GetUserPasswordHash returns the user and Argon2id hash by id.
func GetUserPasswordHash(ctx context.Context, db *sql.DB, id string) (User, string, error) {
	row := db.QueryRowContext(ctx, `SELECT id, principal_type, email, display_name, roles_json, disabled,
		must_change_password, failed_login_count, locked_until, last_login_at, password_changed_at,
		created_at, created_by, updated_at, updated_by, password_hash
		FROM users WHERE id=?`, id)
	return scanUserWithHash(row)
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUserWithHash(row userScanner) (User, string, error) {
	var (
		u                    User
		rolesJSON            string
		disabled, mustChange int
		hash                 string
	)
	err := row.Scan(&u.ID, &u.PrincipalType, &u.Email, &u.DisplayName, &rolesJSON, &disabled,
		&mustChange, &u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.PasswordChangedAt,
		&u.CreatedAt, &u.CreatedBy, &u.UpdatedAt, &u.UpdatedBy, &hash)
	if err != nil {
		return User{}, "", err
	}
	_ = json.Unmarshal([]byte(rolesJSON), &u.Roles)
	u.Disabled = disabled == 1
	u.MustChangePassword = mustChange == 1
	u.HasPassword = hash != ""
	return u, hash, nil
}

func scanUser(row userScanner) (User, error) {
	u, _, err := scanUserWithHash(row)
	return u, err
}

// CreateUserInput for administrator-driven identity create.
type CreateUserInput struct {
	Email              string
	DisplayName        string
	Roles              []string
	Password           string // optional; generated when empty
	MustChangePassword bool
	ActorID            string
}

// CreateUser inserts a workforce user. Returns the user and plaintext temp password when generated.
func CreateUser(ctx context.Context, db *sql.DB, in CreateUserInput) (User, string, error) {
	email := strings.TrimSpace(in.Email)
	if email == "" {
		return User{}, "", fmt.Errorf("email required")
	}
	roles := normalizeRoles(in.Roles)
	if len(roles) == 0 {
		return User{}, "", fmt.Errorf("at least one role required")
	}
	pass := in.Password
	temp := ""
	if pass == "" {
		var err error
		pass, err = GenerateTempPassword()
		if err != nil {
			return User{}, "", err
		}
		temp = pass
		in.MustChangePassword = true
	}
	if err := ValidatePasswordPolicy(pass, email); err != nil {
		return User{}, "", err
	}
	hash, err := HashPassword(pass)
	if err != nil {
		return User{}, "", err
	}
	id := uuid.Must(uuid.NewV7()).String()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	rolesJSON, _ := json.Marshal(roles)
	must := 0
	if in.MustChangePassword || temp != "" {
		must = 1
	}
	display := in.DisplayName
	if display == "" {
		display = email
	}
	_, err = db.ExecContext(ctx, `INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled,
		created_at, created_by, updated_at, updated_by, password_hash, password_changed_at, must_change_password,
		failed_login_count, locked_until, last_login_at)
		VALUES(?,?,?,?,?,0,?,?,?,?,?,?,?,0,'','')`,
		id, "workforce", email, display, string(rolesJSON), ts, in.ActorID, ts, in.ActorID,
		hash, ts, must)
	if err != nil {
		return User{}, "", err
	}
	u, err := GetUser(ctx, db, id)
	return u, temp, err
}

// UpdateUserPatch updates display name, roles, and/or disabled flag.
type UpdateUserPatch struct {
	DisplayName *string
	Roles       *[]string
	Disabled    *bool
	ActorID     string
}

// UpdateUser applies a patch.
func UpdateUser(ctx context.Context, db *sql.DB, id string, patch UpdateUserPatch) (User, error) {
	u, err := GetUser(ctx, db, id)
	if err != nil {
		return User{}, err
	}
	if patch.DisplayName != nil {
		u.DisplayName = *patch.DisplayName
	}
	if patch.Roles != nil {
		u.Roles = normalizeRoles(*patch.Roles)
	}
	if patch.Disabled != nil {
		u.Disabled = *patch.Disabled
	}
	rolesJSON, _ := json.Marshal(u.Roles)
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	dis := 0
	if u.Disabled {
		dis = 1
	}
	_, err = db.ExecContext(ctx, `UPDATE users SET display_name=?, roles_json=?, disabled=?, updated_at=?, updated_by=? WHERE id=?`,
		u.DisplayName, string(rolesJSON), dis, ts, patch.ActorID, id)
	if err != nil {
		return User{}, err
	}
	return GetUser(ctx, db, id)
}

// SetUserPassword sets a password hash (admin reset or self-change).
func SetUserPassword(ctx context.Context, db *sql.DB, id, password, email, actorID string, mustChange bool) error {
	if err := ValidatePasswordPolicy(password, email); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	must := 0
	if mustChange {
		must = 1
	}
	_, err = db.ExecContext(ctx, `UPDATE users SET password_hash=?, password_changed_at=?, must_change_password=?,
		failed_login_count=0, locked_until='', updated_at=?, updated_by=? WHERE id=?`,
		hash, ts, must, ts, actorID, id)
	return err
}

// RecordLoginFailure increments lockout counters.
func RecordLoginFailure(ctx context.Context, db *sql.DB, id string, now time.Time) error {
	u, hash, err := getUserLockState(ctx, db, id)
	if err != nil {
		return err
	}
	_ = hash
	count := u.FailedLoginCount + 1
	locked := ""
	if count >= MaxFailedLogins {
		locked = now.UTC().Add(time.Duration(LockoutDurationMin) * time.Minute).Format(time.RFC3339Nano)
		count = 0
	}
	_, err = db.ExecContext(ctx, `UPDATE users SET failed_login_count=?, locked_until=? WHERE id=?`, count, locked, id)
	return err
}

// RecordLoginSuccess clears lockout and stamps last login.
func RecordLoginSuccess(ctx context.Context, db *sql.DB, id string, now time.Time) error {
	ts := now.UTC().Format(time.RFC3339Nano)
	_, err := db.ExecContext(ctx, `UPDATE users SET failed_login_count=0, locked_until='', last_login_at=? WHERE id=?`, ts, id)
	return err
}

func getUserLockState(ctx context.Context, db *sql.DB, id string) (User, string, error) {
	u, err := GetUser(ctx, db, id)
	return u, "", err
}

// CheckLoginAllowed returns ErrAccountDisabled / ErrAccountLocked when applicable.
func CheckLoginAllowed(u User, now time.Time) error {
	if u.Disabled {
		return ErrAccountDisabled
	}
	if u.LockedUntil != "" {
		if t, err := time.Parse(time.RFC3339Nano, u.LockedUntil); err == nil && now.Before(t) {
			return ErrAccountLocked
		}
	}
	return nil
}

// RolesTouchAdmin reports whether role set involves admin roles.
func RolesTouchAdmin(before, after []string) bool {
	b := roleSet(before)
	a := roleSet(after)
	for role := range AdminRoles {
		if b[role] != a[role] {
			return true
		}
	}
	return false
}

func roleSet(roles []string) map[string]bool {
	m := map[string]bool{}
	for _, r := range roles {
		m[r] = true
	}
	return m
}

func normalizeRoles(roles []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] || !isAssignableRole(r) {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// VerifySecondAdmin confirms a distinct admin's password for SOD-3.
func VerifySecondAdmin(ctx context.Context, db *sql.DB, actorID, email, password string, now time.Time) error {
	email = strings.TrimSpace(email)
	if email == "" || password == "" {
		return errors.New("second administrator email and password required")
	}
	u, hash, err := GetUserByEmail(ctx, db, email)
	if err != nil {
		return errors.New("second administrator not found")
	}
	if u.ID == actorID {
		return errors.New("second administrator must be a different user")
	}
	if err := CheckLoginAllowed(u, now); err != nil {
		return err
	}
	okAdmin := false
	for _, r := range u.Roles {
		if AdminRoles[r] {
			okAdmin = true
			break
		}
	}
	if !okAdmin {
		return errors.New("second confirmer must be an administrator")
	}
	ok, err := VerifyPassword(hash, password)
	if err != nil || !ok {
		return errors.New("second administrator credentials invalid")
	}
	return nil
}
