package questionnaire

import "testing"

func TestVisibleIfCEL(t *testing.T) {
	env, err := NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	c, err := env.Compile(`engagement.tier <= 2`)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.EvalBool(nil, map[string]any{"tier": int64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected visible for tier 2")
	}
	ok, err = c.EvalBool(nil, map[string]any{"tier": int64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected hidden for tier 3")
	}
}

func TestScoringCEL(t *testing.T) {
	env, err := NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	expr := `answers["IAM-03"] == "yes" ? 1.0 : (answers["IAM-03"] == "partial" ? 0.5 : 0.0)`
	c, err := env.Compile(expr)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ans  string
		want float64
	}{
		{"yes", 1.0},
		{"partial", 0.5},
		{"no", 0.0},
	} {
		got, err := c.EvalNumber(map[string]any{"IAM-03": tc.ans}, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.ans, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.ans, got, tc.want)
		}
	}
}

func TestInvalidCELRejected(t *testing.T) {
	env, err := NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Compile(`answers[`); err == nil {
		t.Fatal("expected compile error")
	}
}
