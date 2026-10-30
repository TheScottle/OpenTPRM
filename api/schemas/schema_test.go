package schemas_test

import (
	"encoding/json"
	"testing"

	"github.com/TheScottle/OpenTPRM/api/schemas"
)

func TestSOCReviewSchemaEmbedded(t *testing.T) {
	raw, err := schemas.FS.ReadFile("soc-review-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["$id"] != "opentprm/soc-review/v1" {
		t.Fatalf("id=%v", doc["$id"])
	}
	req, ok := doc["required"].([]any)
	if !ok || len(req) < 5 {
		t.Fatalf("required=%v", doc["required"])
	}
	defs, ok := doc["$defs"].(map[string]any)
	if !ok {
		t.Fatal("missing $defs")
	}
	for _, name := range []string{"citation", "exception", "cuec", "subservice"} {
		if _, ok := defs[name]; !ok {
			t.Fatalf("missing $defs.%s", name)
		}
	}
}
