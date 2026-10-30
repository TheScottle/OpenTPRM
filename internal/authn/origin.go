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
//   - Sec-Fetch-Site: cross-site → reject
//   - Missing Origin → allow (classic same-origin navigations may omit it)
//   - Origin hostname must match at least one allowed host
//   - Port must match when both sides declare a non-default port; if Sec-Fetch-Site is
//     same-origin / same-site / none, hostname match alone is enough (reverse proxies often
//     rewrite Host to :8443 while the browser Origin uses :443 or omits the port)
func CheckOriginRejectsCrossSite(r *http.Request, allowedHosts ...string) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	sfs := r.Header.Get("Sec-Fetch-Site")
	if sfs == "cross-site" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
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
	sameSiteHint := sfs == "same-origin" || sfs == "same-site" || sfs == "none" || sfs == ""

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// Allow full URLs in public_base_url.
		if strings.Contains(h, "://") {
			if pu, err := url.Parse(h); err == nil && pu.Host != "" {
				h = pu.Host
			}
		}
		wantHost, wantPort := splitHostPort(h)
		if wantHost == "" || wantHost == "0.0.0.0" || wantHost == "::" {
			continue
		}
		if originHost != strings.ToLower(wantHost) {
			continue
		}
		if portsCompatible(originPort, wantPort) {
			return false
		}
		// Browser attested same-site: Host port rewrite behind TLS terminator / Docker publish.
		if sameSiteHint {
			return false
		}
	}
	return true
}

func portsCompatible(originPort, wantPort string) bool {
	if wantPort == "" || wantPort == "443" || wantPort == "80" {
		return true
	}
	if originPort == wantPort {
		return true
	}
	// Origin default https while Host carries backend listen port (e.g. :8443).
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
