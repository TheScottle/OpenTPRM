package config_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/config"
)

func TestOPS_001_ProductionRefusesInsecure(t *testing.T) {
	cfg := config.Default()
	cfg.Mode = config.ModeProduction
	if err := cfg.Validate(); err == nil {
		t.Fatal("production without TLS must fail")
	}
	cfg.Server.Internal.TLS.CertFile = "/c.pem"
	cfg.Server.Internal.TLS.KeyFile = "/k.pem"
	cfg.Keys.MasterKeyFile = "/master"
	cfg.Identity.AllowDevHeaders = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("production must refuse allow_dev_headers")
	}
	cfg.Identity.AllowDevHeaders = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
}

func TestOPS_002_RefuseSecretEnv(t *testing.T) {
	t.Setenv("OPENTPRM_MASTER_KEY", "secret")
	if err := config.RefuseSecretEnv(); err == nil {
		t.Fatal("must refuse secret env")
	}
	t.Setenv("OPENTPRM_MASTER_KEY", "")
	if err := config.RefuseSecretEnv(); err != nil {
		t.Fatal(err)
	}
}
