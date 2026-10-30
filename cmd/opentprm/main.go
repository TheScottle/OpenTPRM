package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/backup"
	"github.com/TheScottle/OpenTPRM/internal/blob"
	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/ctn"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
	"github.com/TheScottle/OpenTPRM/internal/sandbox"
	"github.com/TheScottle/OpenTPRM/internal/seed"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/TheScottle/OpenTPRM/policies"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(log, os.Args[2:])
	case "init":
		err = cmdInit(log, os.Args[2:])
	case "unseal":
		err = fmt.Errorf("unseal: use serve with master key file or restart after placing key")
	case "audit":
		err = cmdAudit(log, os.Args[2:])
	case "healthcheck":
		err = cmdHealthcheck()
	case "sandbox":
		err = cmdSandbox(os.Args[2:])
	case "backup":
		err = cmdBackup(log, os.Args[2:])
	case "restore":
		err = cmdRestore(log, os.Args[2:])
	case "passwd":
		err = cmdPasswd(log, os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("command failed", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `OpenTPRM %s
Usage: opentprm <command> [flags]
Commands: serve | init | unseal | audit | healthcheck | sandbox | backup | restore | passwd | version
`, version)
}

func cmdServe(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/opentprm/config.yaml", "config path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := config.RefuseSecretEnv(); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		// Allow missing config in development via env OPENTPRM_CONFIG or defaults file
		if os.IsNotExist(err) {
			cfg = config.Default()
			log.Warn("config not found; using defaults", "path", *cfgPath)
		} else {
			return err
		}
	}

	st := ctn.Run(cfg.Mode == config.ModeProduction, cfg.Storage.DataDir, "")
	if cfg.Mode == config.ModeProduction && !st.OK {
		return fmt.Errorf("SEC-CTN-006 self-test failed: %v", st.Failures)
	}
	for _, w := range st.Warnings {
		log.Warn("self-test", "warning", w)
	}

	keyring := crypto.NewSealed()
	sealed := true
	if cfg.Keys.MasterKeyFile != "" {
		if err := keyring.UnsealFromFile(cfg.Keys.MasterKeyFile); err != nil {
			log.Warn("sealed mode: cannot load master key", "err", err.Error())
		} else {
			sealed = false
		}
	}

	// OPS-004: refuse demo org seed in production before opening store work.
	if err := seed.AllowDemo(cfg.Mode); err != nil {
		return err
	}

	var stStore *store.Store
	var auditLog *audit.Logger
	if !sealed {
		stStore, err = store.Open(cfg.Storage.DataDir, keyring)
		if err != nil {
			return err
		}
		defer stStore.Close()
		auditLog = audit.New(stStore.DB(), keyring)
		if seed.Requested() {
			seedCtx := authz.WithContext(context.Background(), authz.Context{
				PrincipalID: "system", PrincipalType: authz.PrincipalWorkforce,
				Roles: []string{"security_administrator"}, AAL: 2,
			})
			if err := seed.ApplyDemo(seedCtx, cfg.Mode, func(ctx context.Context, v seed.DemoVendor) error {
				return stStore.CreateVendor(ctx, store.Vendor{
					LegalName:   v.LegalName,
					AliasesJSON: `["` + v.TradeName + `"]`,
					TagsJSON:    `["demo","ops-004"]`,
					CreatedBy:   "system", UpdatedBy: "system",
				})
			}); err != nil {
				return err
			}
			log.Info("demo seed applied", "org", seed.DemoOrgLegalName)
		}
	}

	policyText, err := policies.Base()
	if err != nil {
		return err
	}
	pdp, err := authz.NewPDP(policyText)
	if err != nil {
		return fmt.Errorf("cedar: %w", err)
	}

	var sessions *authn.SessionStore
	var credentials *authn.CredentialStore
	var blobs *blob.Store
	if stStore != nil {
		sessions = authn.NewSessionStore(stStore.DB())
		credentials = authn.NewCredentialStore(stStore.DB())
	}
	if !sealed && keyring != nil {
		blobs = &blob.Store{Root: cfg.Storage.DataDir, KEK: keyring.BlobKEK}
	}
	// Production Validate refuses identity.allow_dev_headers; never honor X-OpenTPRM-* there.
	allowDev := cfg.Mode != config.ModeProduction
	if cfg.Mode != config.ModeProduction && cfg.Identity.OIDC.Issuer != "" && !cfg.Identity.AllowDevHeaders {
		allowDev = false
	}
	app := &httpserver.App{
		Cfg:             cfg,
		Keyring:         keyring,
		Store:           stStore,
		Blobs:           blobs,
		Audit:           auditLog,
		PDP:             pdp,
		Log:             log,
		SealedMode:      sealed,
		Sessions:        sessions,
		Challenges:      authn.NewChallengeStore(),
		Credentials:     credentials,
		BreakGlass:      authn.NewBreakGlassRegistry(),
		Idempotency:     httpserver.NewIdempotencyStore(24 * time.Hour),
		AllowDevHeaders: allowDev,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cert, key := cfg.Server.Internal.TLS.CertFile, cfg.Server.Internal.TLS.KeyFile
	log.Info("opentprm serve", "version", version, "listen", cfg.Server.Internal.Listen, "sealed", sealed, "mode", cfg.Mode)
	return app.ListenAndServeTLS(ctx, cert, key)
}

func cmdInit(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dataDir := fs.String("data", "./data", "data directory")
	outKey := fs.String("master-key", "./secrets/master.key", "master key output path")
	tlsDir := fs.String("tls-dir", "./secrets", "directory for self-signed TLS material")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*outKey), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(*tlsDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(*outKey); err == nil {
		return fmt.Errorf("master key already exists at %s", *outKey)
	}
	if err := crypto.GenerateMasterKey(*outKey); err != nil {
		return err
	}
	certFile := filepath.Join(*tlsDir, "tls.crt")
	keyFile := filepath.Join(*tlsDir, "tls.key")
	fp, err := writeSelfSigned(certFile, keyFile)
	if err != nil {
		return err
	}
	token, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	tokenHex := hex.EncodeToString(token)
	tokenPath := filepath.Join(*dataDir, "bootstrap.token")
	if err := os.WriteFile(tokenPath, []byte(tokenHex), 0o400); err != nil {
		return err
	}
	// Register hashed bootstrap token in DB when master key is available (OPS-003).
	kr := crypto.NewSealed()
	if err := kr.UnsealFromFile(*outKey); err == nil {
		if st, err := store.Open(*dataDir, kr); err == nil {
			_ = authn.RegisterBootstrapToken(context.Background(), st.DB(), tokenHex, time.Now().UTC())
			_ = st.Close()
		}
	}
	log.Info("initialized", "master_key", *outKey, "tls_fingerprint", fp, "bootstrap_token", tokenPath, "bootstrap_ttl", "1h")
	return nil
}

func writeSelfSigned(certFile, keyFile string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "opentprm.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	certOut, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", err
	}
	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o400)
	if err != nil {
		return "", err
	}
	defer keyOut.Close()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return "", err
	}
	sum := fmt.Sprintf("%x", der[:16])
	return sum, nil
}

// cmdPasswd sets a workforce user's password (recovery for pre-password bootstrap installs).
func cmdPasswd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/opentprm/config.yaml", "config path")
	email := fs.String("email", "", "user email")
	passFile := fs.String("password-file", "", "path to password file (0400); stdin if empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*email) == "" {
		return fmt.Errorf("--email required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = config.Default()
		} else {
			return err
		}
	}
	if cfg.Keys.MasterKeyFile == "" {
		return fmt.Errorf("keys.master_key_file required")
	}
	kr := crypto.NewSealed()
	if err := kr.UnsealFromFile(cfg.Keys.MasterKeyFile); err != nil {
		return err
	}
	st, err := store.Open(cfg.Storage.DataDir, kr)
	if err != nil {
		return err
	}
	defer st.Close()

	var pass string
	if *passFile != "" {
		b, err := os.ReadFile(*passFile)
		if err != nil {
			return err
		}
		pass = strings.TrimSpace(string(b))
	} else {
		fmt.Fprint(os.Stderr, "New password (≥15 chars): ")
		var line string
		if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
			return err
		}
		pass = strings.TrimSpace(line)
	}
	u, _, err := authn.GetUserByEmail(context.Background(), st.DB(), *email)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if err := authn.SetUserPassword(context.Background(), st.DB(), u.ID, pass, u.Email, "cli:passwd", false); err != nil {
		return err
	}
	log.Info("password updated", "email", u.Email, "user_id", u.ID)
	fmt.Fprintf(os.Stdout, "Password set for %s. Sign in at /login.\n", u.Email)
	return nil
}

func cmdAudit(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/opentprm/config.yaml", "config path")
	dataDir := fs.String("data", "", "override data dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sub := "verify"
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}
	cfg := config.Default()
	if c, err := config.Load(*cfgPath); err == nil {
		cfg = c
	}
	if *dataDir != "" {
		cfg.Storage.DataDir = *dataDir
	}
	if cfg.Keys.MasterKeyFile == "" {
		return fmt.Errorf("master key required for audit verify")
	}
	kr := crypto.NewSealed()
	if err := kr.UnsealFromFile(cfg.Keys.MasterKeyFile); err != nil {
		return err
	}
	st, err := store.Open(cfg.Storage.DataDir, kr)
	if err != nil {
		return err
	}
	defer st.Close()
	al := audit.New(st.DB(), kr)
	switch sub {
	case "verify":
		res, err := al.Verify(context.Background())
		if err != nil {
			return err
		}
		if !res.OK {
			log.Error("audit chain failure", "id", res.FailedAtID, "reason", res.FailedReason, "checked", res.Checked)
			return fmt.Errorf("audit verify failed")
		}
		log.Info("audit chain ok", "checked", res.Checked)
		return nil
	default:
		return fmt.Errorf("unknown audit subcommand %q", sub)
	}
}

func cmdHealthcheck() error {
	// Container HEALTHCHECK: process is up.
	fmt.Println("ok")
	return nil
}

func cmdBackup(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/opentprm/config.yaml", "config path")
	dataDir := fs.String("data", "", "override data dir")
	backupDir := fs.String("backup-dir", "", "override backup dir")
	masterKey := fs.String("master-key", "", "master key file")
	recipient := fs.String("recipient", "", "age recipient (age1...)")
	identityOut := fs.String("write-identity", "", "optional path to write a new age identity when --recipient omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Default()
	if c, err := config.Load(*cfgPath); err == nil {
		cfg = c
	}
	if *dataDir != "" {
		cfg.Storage.DataDir = *dataDir
	}
	if *backupDir != "" {
		cfg.Storage.BackupDir = *backupDir
	}
	keyFile := *masterKey
	if keyFile == "" {
		keyFile = cfg.Keys.MasterKeyFile
	}
	if keyFile == "" {
		return fmt.Errorf("master key required (--master-key)")
	}
	kr := crypto.NewSealed()
	if err := kr.UnsealFromFile(keyFile); err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.Storage.DataDir, "opentprm.db")
	var recipients []age.Recipient
	if *recipient != "" {
		r, err := age.ParseX25519Recipient(*recipient)
		if err != nil {
			return err
		}
		recipients = append(recipients, r)
	} else {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		recipients = append(recipients, id.Recipient())
		out := *identityOut
		if out == "" {
			out = filepath.Join(cfg.Storage.BackupDir, "custodian.agekey")
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(out, []byte(id.String()+"\n"), 0o400); err != nil {
			return err
		}
		log.Info("generated custodian age identity", "path", out, "recipient", id.Recipient().String())
	}
	m, err := backup.CreateOnlineSnapshot(dbPath, cfg.Storage.BackupDir, recipients, kr.SigningPriv)
	if err != nil {
		return err
	}
	log.Info("backup complete", "db_sha256", m.DBSHA256, "files", len(m.Files), "backup_dir", cfg.Storage.BackupDir)
	return nil
}

func cmdRestore(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/opentprm/config.yaml", "config path")
	backupDir := fs.String("backup-dir", "", "backup directory")
	manifest := fs.String("manifest", "", "manifest path (default: newest)")
	masterKey := fs.String("master-key", "", "master key file")
	identityPath := fs.String("identity", "", "age identity file")
	verifyOnly := fs.Bool("verify-only", false, "ARC-013 restore drill without writing live data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*verifyOnly {
		return fmt.Errorf("full restore not enabled in this build; use --verify-only for ARC-013 drills")
	}
	cfg := config.Default()
	if c, err := config.Load(*cfgPath); err == nil {
		cfg = c
	}
	if *backupDir != "" {
		cfg.Storage.BackupDir = *backupDir
	}
	keyFile := *masterKey
	if keyFile == "" {
		keyFile = cfg.Keys.MasterKeyFile
	}
	if keyFile == "" {
		return fmt.Errorf("master key required (--master-key)")
	}
	if *identityPath == "" {
		return fmt.Errorf("--identity required for verify-only decrypt")
	}
	kr := crypto.NewSealed()
	if err := kr.UnsealFromFile(keyFile); err != nil {
		return err
	}
	raw, err := os.ReadFile(*identityPath)
	if err != nil {
		return err
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(raw)))
	if err != nil || len(ids) == 0 {
		return fmt.Errorf("parse age identity: %w", err)
	}
	manPath := *manifest
	if manPath == "" {
		manPath, err = backup.NewestManifest(cfg.Storage.BackupDir)
		if err != nil {
			return err
		}
	}
	m, err := backup.VerifyDrill(manPath, cfg.Storage.BackupDir, kr.SigningPub, ids[0])
	if err != nil {
		return err
	}
	log.Info("restore verify-only ok", "manifest", manPath, "db_sha256", m.DBSHA256, "files", len(m.Files))
	return nil
}

func cmdSandbox(args []string) error {
	// Parser child entrypoint (M3): Landlock/no_new_privs hooks + empty-env parent.
	// Full seccomp BPF remains in deploy/seccomp-opentprm.json around the container.
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	jobID := fs.String("job", "", "job id")
	input := fs.String("input", "", "absolute input path")
	var allows []string
	fs.Func("allow", "allow-listed path (repeatable)", func(v string) error {
		allows = append(allows, v)
		return nil
	})
	_ = fs.Parse(args)
	// Back-compat: `opentprm sandbox <job> <input>`
	if *jobID == "" && fs.NArg() >= 1 {
		*jobID = fs.Arg(0)
	}
	if *input == "" && fs.NArg() >= 2 {
		*input = fs.Arg(1)
	}
	if *jobID == "" {
		return fmt.Errorf("sandbox: missing job id")
	}
	if *input == "" {
		*input = "/dev/null"
	}
	if len(allows) == 0 {
		allows = []string{*input}
	}
	c := sandbox.Constraints{AllowPaths: allows, ForbidNetwork: true}
	if err := sandbox.ValidateJob(sandbox.Job{ID: *jobID, InputPath: *input}, c); err != nil {
		return err
	}
	st, err := sandbox.ApplyChildHooks(c)
	if err != nil {
		return err
	}
	pol := sandbox.ExpectedChildPolicy(c)
	fmt.Printf("sandbox ok job=%s landlock=%v degraded=%v seccomp=%d profile=%s\n",
		*jobID, st.LandlockApplied, st.Degraded, st.SeccompMode, pol.SeccompProfile)
	// PDFium-free path: extract TXT/JSON page text inside the constrained child.
	if *input != "" && *input != "/dev/null" {
		if res, err := sandbox.ExtractTextFile(*input); err == nil {
			fmt.Printf("extract media=%s pages=%d\n", res.MediaType, len(res.Pages))
			for i, page := range res.Pages {
				if len(page) > 120 {
					page = page[:120] + "…"
				}
				fmt.Printf("page %d: %s\n", i+1, page)
			}
		}
	}
	return nil
}
