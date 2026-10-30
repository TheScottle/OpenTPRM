package questionnaire

import (
	"fmt"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// Env wraps a CEL environment for questionnaire expressions.
type Env struct {
	env *cel.Env
}

// Compiled is a type-checked CEL program.
type Compiled struct {
	prg cel.Program
}

// NewEnv builds a sandboxed CEL env over answers + engagement maps.
func NewEnv() (*Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("answers", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("engagement", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, err
	}
	return &Env{env: env}, nil
}

// Compile type-checks an expression (QST-003).
func (e *Env) Compile(expr string) (*Compiled, error) {
	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	prg, err := e.env.Program(ast, cel.CostLimit(100000))
	if err != nil {
		return nil, err
	}
	return &Compiled{prg: prg}, nil
}

// EvalBool evaluates to bool.
func (c *Compiled) EvalBool(answers map[string]any, engagement map[string]any) (bool, error) {
	if answers == nil {
		answers = map[string]any{}
	}
	if engagement == nil {
		engagement = map[string]any{}
	}
	out, _, err := c.prg.Eval(map[string]any{"answers": answers, "engagement": engagement})
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expected bool, got %T", out.Value())
	}
	return b, nil
}

// EvalNumber evaluates to float64.
func (c *Compiled) EvalNumber(answers map[string]any, engagement map[string]any) (float64, error) {
	if answers == nil {
		answers = map[string]any{}
	}
	if engagement == nil {
		engagement = map[string]any{}
	}
	out, _, err := c.prg.Eval(map[string]any{"answers": answers, "engagement": engagement})
	if err != nil {
		return 0, err
	}
	return asFloat(out)
}

func asFloat(v ref.Val) (float64, error) {
	switch t := v.Value().(type) {
	case float64:
		return t, nil
	case int64:
		return float64(t), nil
	case types.Double:
		return float64(t), nil
	default:
		// CEL numeric types
		if d, ok := v.(types.Double); ok {
			return float64(d), nil
		}
		if i, ok := v.(types.Int); ok {
			return float64(i), nil
		}
		return 0, fmt.Errorf("expected number, got %T", v.Value())
	}
}

// EvalBool is a convenience one-shot helper.
func EvalBool(expr string, answers, engagement map[string]any) (bool, error) {
	env, err := NewEnv()
	if err != nil {
		return false, err
	}
	c, err := env.Compile(expr)
	if err != nil {
		return false, err
	}
	return c.EvalBool(answers, engagement)
}
