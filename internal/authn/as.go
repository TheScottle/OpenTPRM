package authn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrTokenNotFound      = errors.New("oauth token not found or revoked")
	ErrTokenExpired       = errors.New("oauth token expired")
	ErrMissingDPoP        = errors.New("DPoP proof header required")
	ErrBearerNotAllowed   = errors.New("bearer-only tokens refused; use DPoP")
	ErrInvalidAudience    = errors.New("token audience mismatch")
)

// AccessTokenTTL is the default opaque access-token lifetime (AI-023).
const AccessTokenTTL = 10 * time.Minute

// IssuedToken is returned once in plaintext to the client; only the hash is retained.
type IssuedToken struct {
	AccessToken    string
	TokenType      string
	ExpiresIn      int
	Scope          string
	Audience       string
	IDHash         string
	ClientID       string
	UserID         string
	DPoPThumbprint string
	ExpiresAt      time.Time
}

// StoredToken is the hashed-at-rest access token record (AI-023).
type StoredToken struct {
	IDHash         string
	ClientID       string
	UserID         string
	Scopes         []string
	Audience       string
	DPoPThumbprint string
	ExpiresAt      time.Time
	Revoked        bool
}

// AuthorizationServer issues and verifies opaque, hashed access tokens (M6 / AI-023).
// PKCE + auth codes for pre-registered clients and DPoP proof verify are supported;
// refresh rotation + mTLS client-cred stubs are available; full fosite remains open.
type AuthorizationServer struct {
	mu     sync.RWMutex
	tokens map[string]StoredToken
	TTL    time.Duration
	// RequireSenderConstraint refuses Authorization without a DPoP proof header (AI-023).
	RequireSenderConstraint bool
	Clients                 *ClientRegistry
	Codes                   *AuthCodeStore
	DPoPNonces              *DPoPNonceStore
	Refresh                 *RefreshStore
	// RequireMTLSForClientCredentials enforces peer cert on client_credentials (RFC 8705 stub).
	RequireMTLSForClientCredentials bool
	// VerifyDPoPProof when true runs ParseAndVerifyDPoP instead of header-presence stub.
	VerifyDPoPProof bool
}

// NewAuthorizationServer constructs an in-memory AS token store.
func NewAuthorizationServer(ttl time.Duration, requireSender bool) *AuthorizationServer {
	if ttl <= 0 {
		ttl = AccessTokenTTL
	}
	return &AuthorizationServer{
		tokens:                  map[string]StoredToken{},
		TTL:                     ttl,
		RequireSenderConstraint: requireSender,
		Clients:                 NewClientRegistry(),
		Codes:                   NewAuthCodeStore(10 * time.Minute),
		DPoPNonces:              NewDPoPNonceStore(10 * time.Minute),
		Refresh:                 NewRefreshStore(RefreshTTL),
		VerifyDPoPProof:         true,
	}
}

// IssueOpaqueAccessToken mints a 256-bit opaque reference and stores only its hash.
func (as *AuthorizationServer) IssueOpaqueAccessToken(clientID, userID, audience string, scopes []string, dpopThumbprint string) (IssuedToken, error) {
	if as == nil {
		return IssuedToken{}, errors.New("authorization server nil")
	}
	if as.RequireSenderConstraint && strings.TrimSpace(dpopThumbprint) == "" {
		return IssuedToken{}, ErrMissingDPoP
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return IssuedToken{}, err
	}
	token := hex.EncodeToString(raw)
	hash := HashToken(token)
	exp := time.Now().UTC().Add(as.TTL)
	st := StoredToken{
		IDHash: hash, ClientID: clientID, UserID: userID,
		Scopes: append([]string(nil), scopes...), Audience: audience,
		DPoPThumbprint: dpopThumbprint, ExpiresAt: exp,
	}
	as.mu.Lock()
	as.tokens[hash] = st
	as.mu.Unlock()
	return IssuedToken{
		AccessToken: token, TokenType: "DPoP", ExpiresIn: int(as.TTL.Seconds()),
		Scope: strings.Join(scopes, " "), Audience: audience, IDHash: hash,
		ClientID: clientID, UserID: userID, DPoPThumbprint: dpopThumbprint, ExpiresAt: exp,
	}, nil
}

// VerifyOpaqueAccessToken looks up by hash, checks expiry/revocation/audience, and DPoP.
func (as *AuthorizationServer) VerifyOpaqueAccessToken(r *http.Request, expectedAudience string) (StoredToken, error) {
	if as == nil {
		return StoredToken{}, errors.New("authorization server nil")
	}
	authz := r.Header.Get("Authorization")
	scheme, raw, ok := strings.Cut(authz, " ")
	if !ok || raw == "" {
		return StoredToken{}, ErrTokenNotFound
	}
	scheme = strings.TrimSpace(scheme)
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(scheme) {
	case "dpop":
		// ok
	case "bearer":
		if as.RequireSenderConstraint {
			return StoredToken{}, ErrBearerNotAllowed
		}
	default:
		return StoredToken{}, ErrTokenNotFound
	}
	hash := HashToken(raw)
	as.mu.RLock()
	st, ok := as.tokens[hash]
	as.mu.RUnlock()
	if !ok || st.Revoked {
		return StoredToken{}, ErrTokenNotFound
	}
	if time.Now().UTC().After(st.ExpiresAt) {
		return StoredToken{}, ErrTokenExpired
	}
	if expectedAudience != "" && st.Audience != expectedAudience {
		return StoredToken{}, ErrInvalidAudience
	}
	if as.RequireSenderConstraint {
		if as.VerifyDPoPProof {
			proof, err := ParseAndVerifyDPoP(r, raw, as.DPoPNonces)
			if err != nil {
				return StoredToken{}, err
			}
			if st.DPoPThumbprint != "" && st.DPoPThumbprint != proof.Thumbprint {
				return StoredToken{}, ErrDPoPThumbMismatch
			}
		} else if err := CheckDPoPHeaderPresent(r, true); err != nil {
			return StoredToken{}, err
		}
	}
	return st, nil
}

// ExtractDPoPThumbprint verifies (or stubs) the DPoP header and returns a thumbprint for token issue.
func (as *AuthorizationServer) ExtractDPoPThumbprint(r *http.Request) (string, error) {
	if as == nil {
		return "", errors.New("authorization server nil")
	}
	if !as.RequireSenderConstraint {
		if dpop := strings.TrimSpace(r.Header.Get("DPoP")); dpop != "" {
			return HashToken(dpop)[:32], nil
		}
		return "", nil
	}
	if as.VerifyDPoPProof {
		proof, err := ParseAndVerifyDPoP(r, "", as.DPoPNonces)
		if err != nil {
			return "", err
		}
		return proof.Thumbprint, nil
	}
	if err := CheckDPoPHeaderPresent(r, true); err != nil {
		return "", err
	}
	return HashToken(r.Header.Get("DPoP"))[:32], nil
}

// RevokeByHash marks a token revoked.
func (as *AuthorizationServer) RevokeByHash(idHash string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if st, ok := as.tokens[idHash]; ok {
		st.Revoked = true
		as.tokens[idHash] = st
	}
}

// CheckDPoPHeaderPresent is a stub that requires the DPoP HTTP header when sender-constraint is on.
// Full JWS proof validation (ath/htm/htu/jti) remains open (RFC 9449).
func CheckDPoPHeaderPresent(r *http.Request, require bool) error {
	if !require {
		return nil
	}
	if strings.TrimSpace(r.Header.Get("DPoP")) == "" {
		return ErrMissingDPoP
	}
	return nil
}
