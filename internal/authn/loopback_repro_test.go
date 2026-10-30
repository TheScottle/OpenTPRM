package authn_test

import (
	"net/http"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestLoopback_Localhost127Equivalent(t *testing.T) {
	cases := []struct {
		name, host, origin, sfs string
		reject                  bool
	}{
		{"host_localhost_origin_127", "localhost:8443", "https://127.0.0.1:8443", "same-origin", false},
		{"host_127_origin_localhost", "127.0.0.1:8443", "https://localhost:8443", "same-origin", false},
		{"both_127", "127.0.0.1:8443", "https://127.0.0.1:8443", "same-origin", false},
		{"both_localhost", "localhost:8443", "https://localhost:8443", "same-origin", false},
		{"host_127_origin_ipv6", "127.0.0.1:8443", "https://[::1]:8443", "same-origin", false},
		{"matching_origin_ignores_sfs_cross", "127.0.0.1:8443", "https://127.0.0.1:8443", "cross-site", false},
		{"evil_still_rejected", "127.0.0.1:8443", "https://evil.example", "cross-site", true},
		{"cross_site_no_origin", "127.0.0.1:8443", "", "cross-site", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "https://x/login", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.sfs != "" {
				r.Header.Set("Sec-Fetch-Site", c.sfs)
			}
			got := authn.CheckOriginRejectsCrossSite(r, c.host)
			if got != c.reject {
				t.Fatalf("Host=%s Origin=%s SFS=%s reject=%v want %v", c.host, c.origin, c.sfs, got, c.reject)
			}
		})
	}
}
