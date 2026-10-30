package egress_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/egress"
)

func TestAT_12_DisabledConnectorBlocked(t *testing.T) {
	c := egress.New("none", nil)
	if c.Allowed("example.com:443") {
		t.Fatal("mode=none must block")
	}
	_, err := c.Dial("tcp", "example.com:443")
	if err == nil {
		t.Fatal("dial must fail")
	}
}

func TestAllowlist(t *testing.T) {
	c := egress.New("allowlist", []string{"login.microsoftonline.com:443"})
	if !c.Allowed("login.microsoftonline.com:443") {
		t.Fatal("expected allow")
	}
	if c.Allowed("evil.example:443") {
		t.Fatal("expected deny")
	}
}
