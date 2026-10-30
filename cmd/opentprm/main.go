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

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/ctn"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
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
	case "backup", "restore":
		err = fmt.Errorf("%s: implemented in M4 path; use development backup helper", os.Args[1])
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
Commands: serve | init | unseal | audit | healthcheck | sandbox | backup | restore | version
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

	var stStore *store.Store
	var auditLog *audit.Logger
	if !sealed {
		stStore, err = store.Open(cfg.Storage.DataDir, keyring)
		if err != nil {
			return err
		}
		defer stStore.Close()
		auditLog = audit.New(stStore.DB(), keyring)
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
	if stStore != nil {
		sessions = authn.NewSessionStore(stStore.DB())
	}
	app := &httpserver.App{
		Cfg:             cfg,
		Keyring:         keyring,
		Store:           stStore,
		Audit:           auditLog,
		PDP:             pdp,
		Log:             log,
		SealedMode:      sealed,
		Sessions:        sessions,
		Challenges:      authn.NewChallengeStore(),
		BreakGlass:      authn.NewBreakGlassRegistry(),
		AllowDevHeaders: cfg.Mode != config.ModeProduction,
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

func cmdSandbox(args []string) error {
	// Parser child entrypoint (M3). Refuses network implicitly via seccomp in deploy profile.
	if len(args) == 0 {
		return fmt.Errorf("sandbox: missing job id")
	}
	fmt.Println("sandbox stub", strings.Join(args, " "))
	return nil
}
