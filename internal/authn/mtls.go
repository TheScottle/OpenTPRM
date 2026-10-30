package authn

import (
	"crypto/x509"
	"errors"
	"net/http"
)

var (
	ErrMTLSRequired     = errors.New("mTLS client certificate required")
	ErrMTLSUnauthorized = errors.New("mTLS client certificate not authorized")
)

// ClientCertIdentity is extracted from a verified peer certificate (RFC 8705 stub).
type ClientCertIdentity struct {
	Subject   string
	SPIFFEID  string
	RawSHA256 string
}

// RequireClientCertificate stubs RFC 8705 mTLS binding for client_credentials.
// When require is false, missing certs are allowed (dev). When true, PeerCertificates must be present.
func RequireClientCertificate(r *http.Request, require bool) (ClientCertIdentity, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		if require {
			return ClientCertIdentity{}, ErrMTLSRequired
		}
		return ClientCertIdentity{}, nil
	}
	cert := r.TLS.PeerCertificates[0]
	id := ClientCertIdentity{Subject: cert.Subject.String()}
	if spiffe := spiffeURI(cert); spiffe != "" {
		id.SPIFFEID = spiffe
	}
	return id, nil
}

func spiffeURI(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, u := range cert.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// BindTokenToCertThumbprint documents sender-constraint via mTLS (alternative to DPoP).
// Stub: returns a stable placeholder from the leaf subject DN when a cert is present.
func BindTokenToCertThumbprint(r *http.Request) (string, error) {
	id, err := RequireClientCertificate(r, true)
	if err != nil {
		return "", err
	}
	if id.SPIFFEID != "" {
		return HashToken(id.SPIFFEID)[:32], nil
	}
	if id.Subject == "" {
		return "", ErrMTLSUnauthorized
	}
	return HashToken(id.Subject)[:32], nil
}
