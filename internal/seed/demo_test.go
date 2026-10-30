package seed_test

import (
	"context"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/seed"
)

func TestOPS_004_DemoSeedRefusedInProduction(t *testing.T) {
	t.Setenv(seed.EnvDemo, "1")
	if err := seed.AllowDemo(config.ModeProduction); err != seed.ErrProductionDemo {
		t.Fatalf("want ErrProductionDemo, got %v", err)
	}
	if err := seed.AllowDemo(config.ModeDevelopment); err != nil {
		t.Fatal(err)
	}
	called := false
	err := seed.ApplyDemo(context.Background(), config.ModeProduction, func(ctx context.Context, v seed.DemoVendor) error {
		called = true
		return nil
	})
	if err != seed.ErrProductionDemo || called {
		t.Fatalf("production apply: err=%v called=%v", err, called)
	}
	err = seed.ApplyDemo(context.Background(), config.ModeDevelopment, func(ctx context.Context, v seed.DemoVendor) error {
		if v.LegalName != seed.DemoOrgLegalName {
			t.Fatalf("org: %s", v.LegalName)
		}
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("dev apply: err=%v called=%v", err, called)
	}
}

func TestOPS_004_DemoNotRequested(t *testing.T) {
	t.Setenv(seed.EnvDemo, "")
	if seed.Requested() {
		t.Fatal("not requested")
	}
	if err := seed.AllowDemo(config.ModeProduction); err != nil {
		t.Fatal(err)
	}
}

func TestOPS_004_RicherSterlingVanceDemoGraphDevOnly(t *testing.T) {
	t.Setenv(seed.EnvDemo, "1")
	g := seed.DemoGraphSeed()
	if g.Org.LegalName != seed.DemoOrgLegalName {
		t.Fatalf("org: %s", g.Org.LegalName)
	}
	if len(g.Vendors) < 3 || len(g.Contacts) < 3 || len(g.Engagements) < 3 || len(g.AnswerKeys) < 3 {
		t.Fatalf("graph too thin: %+v", g)
	}
	called := false
	err := seed.ApplyDemoGraph(context.Background(), config.ModeProduction, func(ctx context.Context, graph seed.DemoGraph) error {
		called = true
		return nil
	})
	if err != seed.ErrProductionDemo || called {
		t.Fatalf("production richer seed: err=%v called=%v", err, called)
	}
	err = seed.ApplyDemoGraph(context.Background(), config.ModeDevelopment, func(ctx context.Context, graph seed.DemoGraph) error {
		if graph.Vendors[0].LegalName == "" {
			t.Fatal("missing vendor")
		}
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("dev richer seed: err=%v called=%v", err, called)
	}
}
