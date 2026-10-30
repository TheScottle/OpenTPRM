package questionnaire

import (
	"encoding/json"
	"testing"
)

func TestPublishSOD(t *testing.T) {
	v := TemplateVersion{
		TemplateID: "t1",
		Semver:     "1.0.0",
		Status:     "draft",
		Content:    json.RawMessage(`{"questions":[]}`),
		LastEditor: "alice",
		Provenance: map[string]string{"license": "owner_authored", "source": "OpenTPRM"},
	}
	if _, err := Publish(v, "alice"); err == nil {
		t.Fatal("same editor must fail")
	}
	pub, err := Publish(v, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if pub.Status != "published" || pub.ContentHash == "" {
		t.Fatalf("bad publish: %+v", pub)
	}
}

func TestCELVisibleIf(t *testing.T) {
	ok, err := EvalBool(`answers["HOS-01"] == "yes"`, map[string]any{"HOS-01": "yes"}, map[string]any{})
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
}
