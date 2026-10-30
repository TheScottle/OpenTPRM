package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	ErrOIDCState     = errors.New("oidc: invalid or expired state")
	ErrOIDCTokenHTTP = errors.New("oidc: token endpoint error")
	ErrOIDCNoIDToken = errors.New("oidc: id_token missing")
)

// OIDCClient is a workforce SSO authorization-code + PKCE client (SEC-AN-001).
// Implicit flow is never used.
type OIDCClient struct {
	Cfg        OIDCConfig
	States     *AuthStateStore
	HTTPClient *http.Client
	// AuthorizeURL and TokenURL override discovery (tests / Keycloak paths).
	AuthorizeURL string
	TokenURL     string
	// JWKSKey is the IdP signing key used to verify id_token (tests inject; production loads JWKS).
	JWKSKey any
}

// AuthStart is the browser redirect target plus server-side state handle.
type AuthStart struct {
	RedirectURL string
	StateID     string
	Nonce       string
	Verifier    string
}

// TokenResponse is the authorization-code exchange result.
type TokenResponse struct {
	AccessToken string
	IDToken     string
	TokenType   string
	ExpiresIn   int
	Claims      IDTokenClaims
}

// StartAuthorization builds the authorize redirect (response_type=code, PKCE S256, nonce, state).
func (c *OIDCClient) StartAuthorization(now time.Time) (AuthStart, error) {
	if c == nil || c.Cfg.Issuer == "" || c.Cfg.ClientID == "" || c.Cfg.RedirectURI == "" {
		return AuthStart{}, fmt.Errorf("oidc: incomplete client config")
	}
	if c.States == nil {
		c.States = NewAuthStateStore()
	}
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		return AuthStart{}, err
	}
	nonce := hex.EncodeToString(nonceRaw)
	verifier, challenge, err := PKCEVerifier()
	if err != nil {
		return AuthStart{}, err
	}
	stateID, err := c.States.Put(nonce, verifier, now)
	if err != nil {
		return AuthStart{}, err
	}
	authURL := c.AuthorizeURL
	if authURL == "" {
		authURL = strings.TrimRight(c.Cfg.Issuer, "/") + "/protocol/openid-connect/auth"
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.Cfg.ClientID)
	q.Set("redirect_uri", c.Cfg.RedirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", stateID)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return AuthStart{
		RedirectURL: authURL + "?" + q.Encode(),
		StateID:     stateID,
		Nonce:       nonce,
		Verifier:    verifier,
	}, nil
}

// ExchangeCode completes the callback: take state, POST token endpoint with PKCE verifier, validate id_token.
func (c *OIDCClient) ExchangeCode(stateID, code string, now time.Time) (TokenResponse, error) {
	if c == nil || c.States == nil {
		return TokenResponse{}, ErrOIDCState
	}
	nonce, verifier, ok := c.States.Take(stateID, now)
	if !ok {
		return TokenResponse{}, ErrOIDCState
	}
	tokenURL := c.TokenURL
	if tokenURL == "" {
		tokenURL = strings.TrimRight(c.Cfg.Issuer, "/") + "/protocol/openid-connect/token"
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.Cfg.RedirectURI)
	form.Set("client_id", c.Cfg.ClientID)
	form.Set("code_verifier", verifier)

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("%w: status %d", ErrOIDCTokenHTTP, resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return TokenResponse{}, err
	}
	if tok.IDToken == "" {
		return TokenResponse{}, ErrOIDCNoIDToken
	}
	claims, err := c.parseAndValidateIDToken(tok.IDToken, nonce, now)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken: tok.AccessToken,
		IDToken:     tok.IDToken,
		TokenType:   tok.TokenType,
		ExpiresIn:   tok.ExpiresIn,
		Claims:      claims,
	}, nil
}

type idTokenPrivate struct {
	Nonce string   `json:"nonce"`
	ACR   string   `json:"acr"`
	AMR   []string `json:"amr"`
	Email string   `json:"email"`
}

func (c *OIDCClient) parseAndValidateIDToken(raw, expectedNonce string, now time.Time) (IDTokenClaims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA, jose.RS256})
	if err != nil {
		return IDTokenClaims{}, err
	}
	var pub jwt.Claims
	var priv idTokenPrivate
	key := c.JWKSKey
	if key == nil {
		return IDTokenClaims{}, errors.New("oidc: no verification key")
	}
	if err := tok.Claims(key, &pub, &priv); err != nil {
		return IDTokenClaims{}, err
	}
	aud := []string{}
	for _, a := range pub.Audience {
		aud = append(aud, a)
	}
	exp := time.Time{}
	if pub.Expiry != nil {
		exp = pub.Expiry.Time()
	}
	out := IDTokenClaims{
		Iss:   pub.Issuer,
		Aud:   aud,
		Exp:   exp,
		Nonce: priv.Nonce,
		Sub:   pub.Subject,
		ACR:   priv.ACR,
		AMR:   priv.AMR,
		Email: priv.Email,
	}
	if err := ValidateIDTokenClaims(c.Cfg, out, expectedNonce, now); err != nil {
		return IDTokenClaims{}, err
	}
	return out, nil
}

// NewTestECDSAKey mints an ES256 key pair for fake IdP tests.
func NewTestECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SignTestIDToken builds a signed id_token for fake IdP fixtures.
func SignTestIDToken(priv *ecdsa.PrivateKey, claims IDTokenClaims) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	pub := jwt.Claims{
		Issuer:   claims.Iss,
		Subject:  claims.Sub,
		Audience: jwt.Audience(claims.Aud),
		Expiry:   jwt.NewNumericDate(claims.Exp),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
	}
	privCl := idTokenPrivate{Nonce: claims.Nonce, ACR: claims.ACR, AMR: claims.AMR, Email: claims.Email}
	return jwt.Signed(signer).Claims(pub).Claims(privCl).Serialize()
}
