package questionnaire

import (
	"encoding/json"
	"fmt"
)

// DeltaPrefill prepares a reassessment instance from a prior answer set (AT-15).
type DeltaPrefill struct {
	PriorAnswers    map[string]any
	ChangedKeys     []string
	RequiresConfirm []string // unchanged keys that vendor must confirm
}

// BuildDeltaPrefill highlights changes and requires confirmation of unchanged answers.
func BuildDeltaPrefill(prior, current map[string]any) DeltaPrefill {
	d := DeltaPrefill{PriorAnswers: prior}
	for k, v := range prior {
		cv, ok := current[k]
		if !ok {
			d.RequiresConfirm = append(d.RequiresConfirm, k)
			continue
		}
		if fmt.Sprint(canonicalize(v)) != fmt.Sprint(canonicalize(cv)) {
			d.ChangedKeys = append(d.ChangedKeys, k)
		} else {
			d.RequiresConfirm = append(d.RequiresConfirm, k)
		}
	}
	for k := range current {
		if _, ok := prior[k]; !ok {
			d.ChangedKeys = append(d.ChangedKeys, k)
		}
	}
	return d
}

func canonicalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
