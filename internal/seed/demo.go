package seed

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/TheScottle/OpenTPRM/internal/config"
)

// EnvDemo is the v1 demo-org seed switch (OPS-004).
const EnvDemo = "TPRM_SEED_DEMO"

// DemoOrgLegalName is the Sterling & Vance LLP demo tenant.
const DemoOrgLegalName = "Sterling & Vance LLP"

// Requested reports whether TPRM_SEED_DEMO=1 is set.
func Requested() bool {
	v := strings.TrimSpace(os.Getenv(EnvDemo))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// ErrProductionDemo is returned when demo seed is requested under production mode.
var ErrProductionDemo = fmt.Errorf("OPS-004: %s refused when mode=production", EnvDemo)

// AllowDemo returns nil only when demo seed is permitted for the given mode.
func AllowDemo(mode config.Mode) error {
	if !Requested() {
		return nil
	}
	if mode == config.ModeProduction {
		return ErrProductionDemo
	}
	return nil
}

// DemoVendor is a minimal demo org seed payload.
type DemoVendor struct {
	LegalName string `json:"legal_name"`
	TradeName string `json:"trade_name"`
	Notes     string `json:"notes"`
}

// DemoOrg returns the Sterling & Vance LLP seed record (development only).
func DemoOrg() DemoVendor {
	return DemoVendor{
		LegalName: DemoOrgLegalName,
		TradeName: "Sterling & Vance",
		Notes:     "OPS-004 development demo org; never seeded in production",
	}
}

// ApplyDemo is a hook for store-backed seeding; callers must check AllowDemo first.
func ApplyDemo(ctx context.Context, mode config.Mode, apply func(context.Context, DemoVendor) error) error {
	if err := AllowDemo(mode); err != nil {
		return err
	}
	if !Requested() {
		return nil
	}
	if apply == nil {
		return nil
	}
	return apply(ctx, DemoOrg())
}
