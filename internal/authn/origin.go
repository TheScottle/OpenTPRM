package authn

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// CheckOriginRejectsCrossSite rejects state-changing requests that fail Origin / Sec-Fetch-Site.
// allowedHosts are request Host and optional public_base_url / forwarded hosts (host or host:port).
//
// Rules (SEC-WEB):
//   - Missing Origin → allow unless Sec-Fetch-Site is cross-site (classic form navigations omit Origin)
//   - Origin hostname must match an allowed host (loopback aliases treated as equivalent)
//   - When Origin matches the allowlist, allow even if Sec-Fetch-Site says cross-site
//     (browsers can mis-label local HTTPS / Docker loopback; matching Origin is authoritative)
//   - Port: tolerant when hostnames match (proxy / published-port rewrites)
func CheckOriginRejectsCrossSite(r *http.Request, allowedHosts ...string) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	sfs := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")
	if origin == "" {
		return sfs == "cross-site"
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return true
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
	// Expand loopback aliases so Docker Desktop (localhost ↔ 127.0.0.1 ↔ ::1) works.
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
		if portsCompatible(originPort, wantPort) {
			return false
		}
		// Hostname matched (incl. loopback aliases): allow despite port rewrite.
		return false
	}
	return true
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

func portsCompatible(originPort, wantPort string) bool {
	if wantPort == "" || wantPort == "443" || wantPort == "80" {
		return true
	}
	if originPort == wantPort {
		return true
	}
	if originPort == "443" || originPort == "80" {
		return true
	}
	return false
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
