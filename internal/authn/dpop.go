package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	ErrInvalidDPoP       = errors.New("invalid DPoP proof")
	ErrDPoPReplay        = errors.New("DPoP jti replayed")
	ErrDPoPHTMMismatch   = errors.New("DPoP htm mismatch")
	ErrDPoPHTUMismatch   = errors.New("DPoP htu mismatch")
	ErrDPoPThumbMismatch = errors.New("DPoP thumbprint mismatch")
)

// DPoPProof is a verified RFC 9449 proof (claims + JWK thumbprint).
type DPoPProof struct {
	Thumbprint string
	HTM        string
	HTU        string
	JTI        string
	IAT        time.Time
	ATH        string
}

// DPoPNonceStore is a short-lived jti replay cache.
type DPoPNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	TTL  time.Duration
}

// NewDPoPNonceStore constructs a jti cache (default 10m).
func NewDPoPNonceStore(ttl time.Duration) *DPoPNonceStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &DPoPNonceStore{seen: map[string]time.Time{}, TTL: ttl}
}

func (s *DPoPNonceStore) seenOrRemember(jti string) bool {
	if s == nil || jti == "" {
		return false
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[jti]; ok {
		return true
	}
	s.seen[jti] = now.Add(s.TTL)
	return false
}

// ParseAndVerifyDPoP parses the DPoP header as a compact JWS, verifies the
// signature with the embedded JWK (ES256/EdDSA), and checks htm/htu/iat/jti.
// accessToken may be empty (token endpoint); when set, ath must match.
func ParseAndVerifyDPoP(r *http.Request, accessToken string, nonces *DPoPNonceStore) (DPoPProof, error) {
	raw := strings.TrimSpace(r.Header.Get("DPoP"))
	if raw == "" {
		return DPoPProof{}, ErrMissingDPoP
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA})
	if err != nil || len(jws.Signatures) == 0 {
		return DPoPProof{}, ErrInvalidDPoP
	}
	hdr := jws.Signatures[0].Protected
	typ, _ := hdr.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return DPoPProof{}, ErrInvalidDPoP
	}
	if hdr.JSONWebKey == nil || !hdr.JSONWebKey.Valid() {
		return DPoPProof{}, ErrInvalidDPoP
	}
	payload, err := jws.Verify(hdr.JSONWebKey)
	if err != nil {
		return DPoPProof{}, ErrInvalidDPoP
	}
	var claims struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return DPoPProof{}, ErrInvalidDPoP
	}
	if claims.JTI == "" || claims.HTM == "" || claims.HTU == "" || claims.IAT == 0 {
		return DPoPProof{}, ErrInvalidDPoP
	}
	iat := time.Unix(claims.IAT, 0).UTC()
	now := time.Now().UTC()
	if iat.Before(now.Add(-5*time.Minute)) || iat.After(now.Add(2*time.Minute)) {
		return DPoPProof{}, ErrInvalidDPoP
	}
	if !strings.EqualFold(claims.HTM, r.Method) {
		return DPoPProof{}, ErrDPoPHTMMismatch
	}
	wantHTU := dpopHTU(r)
	if normalizeURL(claims.HTU) != normalizeURL(wantHTU) {
		return DPoPProof{}, ErrDPoPHTUMismatch
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		wantATH := base64.RawURLEncoding.EncodeToString(sum[:])
		if claims.ATH == "" || claims.ATH != wantATH {
			return DPoPProof{}, ErrInvalidDPoP
		}
	}
	if nonces != nil && nonces.seenOrRemember(claims.JTI) {
		return DPoPProof{}, ErrDPoPReplay
	}
	thumb, err := hdr.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return DPoPProof{}, ErrInvalidDPoP
	}
	return DPoPProof{
		Thumbprint: hex.EncodeToString(thumb),
		HTM:        claims.HTM,
		HTU:        claims.HTU,
		JTI:        claims.JTI,
		IAT:        iat,
		ATH:        claims.ATH,
	}, nil
}

func dpopHTU(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "http" {
		scheme = "http"
	}
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func normalizeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return strings.TrimRight(u, "/")
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	s := parsed.String()
	return strings.TrimRight(s, "/")
}

// TestDPoPKey is an ES256 keypair used to mint DPoP proofs in tests.
type TestDPoPKey struct {
	Private    *ecdsa.PrivateKey
	Thumbprint string
}

// NewTestDPoPKey generates an ES256 DPoP key for tests.
func NewTestDPoPKey() (*TestDPoPKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := &jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &TestDPoPKey{Private: key, Thumbprint: hex.EncodeToString(thumb)}, nil
}

// Proof signs a DPoP JWT for method/htu; accessToken may be empty at the token endpoint.
func (k *TestDPoPKey) Proof(method, htu, accessToken string) (string, error) {
	if k == nil || k.Private == nil {
		return "", ErrInvalidDPoP
	}
	jwk := &jose.JSONWebKey{Key: &k.Private.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.Private}, opts)
	if err != nil {
		return "", err
	}
	jb := make([]byte, 16)
	_, _ = rand.Read(jb)
	claims := map[string]any{
		"htm": method,
		"htu": htu,
		"jti": hex.EncodeToString(jb),
		"iat": time.Now().UTC().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// MintTestDPoPProof builds a one-shot ES256 DPoP proof for unit tests.
func MintTestDPoPProof(method, htu string, accessToken string) (proofHeader string, thumbprint string, err error) {
	k, err := NewTestDPoPKey()
	if err != nil {
		return "", "", err
	}
	proof, err := k.Proof(method, htu, accessToken)
	if err != nil {
		return "", "", err
	}
	return proof, k.Thumbprint, nil
}
