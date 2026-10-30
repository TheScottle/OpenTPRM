package authn

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// OriginCheckResult explains a CSRF Origin / Sec-Fetch-Site decision.
type OriginCheckResult struct {
	Reject bool
	Reason string // empty when allowed; stable machine code when rejected
	Detail string // human-readable; safe for development responses
}

// CheckOriginRejectsCrossSite reports whether the request should be rejected.
func CheckOriginRejectsCrossSite(r *http.Request, allowedHosts ...string) bool {
	return EvaluateOrigin(r, allowedHosts...).Reject
}

// EvaluateOrigin applies SEC-WEB Origin / Sec-Fetch-Site checks.
//
// Priority:
//  1. Safe methods → allow
//  2. Sec-Fetch-Site same-origin / same-site → allow (forbidden header; browsers only)
//  3. Missing Origin → allow (classic same-origin form posts may omit it)
//  4. Origin must match allowlist (Host, public_base_url, X-Forwarded-Host; loopback aliases equal)
//  5. Sec-Fetch-Site cross-site alone never overrides a matching Origin
func EvaluateOrigin(r *http.Request, allowedHosts ...string) OriginCheckResult {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return OriginCheckResult{}
	}
	sfs := r.Header.Get("Sec-Fetch-Site")
	// Browser-controlled attestation: JS cannot set Sec-Fetch-*. Trust it.
	if sfs == "same-origin" || sfs == "same-site" {
		return OriginCheckResult{}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// No Origin to validate. Do not reject solely on Sec-Fetch-Site — some local
		// HTTPS / privacy browsers omit Origin while still labeling cross-site incorrectly.
		return OriginCheckResult{}
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return OriginCheckResult{
			Reject: true, Reason: "bad_origin",
			Detail: fmt.Sprintf("unparseable Origin %q (Host=%q SFS=%q)", origin, r.Host, sfs),
		}
	}
	originHost := strings.ToLower(u.Hostname())
	originPort := u.Port()
	if originPort == "" {
		if u.Scheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}

	hosts := allowedHosts
	if len(hosts) == 0 {
		hosts = []string{r.Host}
	}
	hosts = expandLoopbackAllowlist(hosts, originHost)

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if strings.Contains(h, "://") {
			if pu, err := url.Parse(h); err == nil && pu.Host != "" {
				h = pu.Host
			}
		}
		wantHost, wantPort := splitHostPort(h)
		if wantHost == "" || wantHost == "0.0.0.0" || wantHost == "::" {
			continue
		}
		if !hostsEquivalent(originHost, wantHost) {
			continue
		}
		_ = wantPort
		return OriginCheckResult{}
	}
	return OriginCheckResult{
		Reject: true, Reason: "origin_not_allowed",
		Detail: fmt.Sprintf("Origin host %q not in allowlist (Host=%q SFS=%q allow=%v)", originHost, r.Host, sfs, hosts),
	}
}

func expandLoopbackAllowlist(hosts []string, originHost string) []string {
	need := isLoopbackHost(originHost)
	if !need {
		for _, h := range hosts {
			hh, _ := authorityHostname(h)
			if isLoopbackHost(hh) {
				need = true
				break
			}
		}
	}
	if !need {
		return hosts
	}
	out := append([]string{}, hosts...)
	out = append(out, "127.0.0.1", "localhost", "::1", "[::1]")
	return out
}

func authorityHostname(h string) (string, string) {
	h = strings.TrimSpace(h)
	if strings.Contains(h, "://") {
		if pu, err := url.Parse(h); err == nil && pu.Host != "" {
			h = pu.Host
		}
	}
	return splitHostPort(h)
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.Trim(host, "[]")
	switch host {
	case "localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func hostsEquivalent(a, b string) bool {
	a = strings.ToLower(strings.Trim(strings.TrimSpace(a), "[]"))
	b = strings.ToLower(strings.Trim(strings.TrimSpace(b), "[]"))
	if a == b {
		return true
	}
	return isLoopbackHost(a) && isLoopbackHost(b)
}

func splitHostPort(hostport string) (host, port string) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", ""
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, ""
}
