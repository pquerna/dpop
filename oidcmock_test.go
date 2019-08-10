package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var discoTmpl = template.Must(template.New("disco").Parse(`{
    "issuer": "{{.}}",
    "authorization_endpoint": "{{.}}/v1/oauth/auth",
    "token_endpoint": "{{.}}/v1/oauth/token",
    "jwks_uri": "{{.}}/v1/oauth/certs",
    "response_types_supported": [
        "code"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "scopes_supported": [
        "email",
        "openid",
        "profile"
    ],
    "claims_supported": [],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post"
    ],
    "grant_types_supported": [
        "authorization_code"
    ]
}`))

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type tokenMinterFunc func(r *http.Request, claims *jwt.Claims) (*tokenResponse, error)

type oidcTestProvider struct {
	t *testing.T

	clientID     string
	clientSecret string

	privateKeyID string
	privateKey   *rsa.PrivateKey

	signingKey jose.SigningKey
	idSigner   jose.Signer
	atSigner   jose.Signer

	server *httptest.Server

	tokenMinter tokenMinterFunc
}

func parseTokenRequestClientIDAndSecret(req *http.Request) (string, string, error) {
	user, secret, ok := req.BasicAuth()
	if !ok {
		return req.FormValue("client_id"), req.FormValue("client_secret"), nil
	}

	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	user, err := url.QueryUnescape(user)
	if err != nil {
		return "", "", err
	}
	secret, err = url.QueryUnescape(secret)
	if err != nil {
		return "", "", err
	}
	return user, secret, nil
}

//https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#appendix-A
func makeJSONWebKey(ID string, pubKey interface{}) (*jose.JSONWebKey, error) {
	var alg string
	switch pubKey.(type) {
	case *rsa.PublicKey:
		alg = "RS256"
	case *ecdsa.PublicKey:
		alg = "ES256"
	default:
		return nil, errors.New("invalid public key type")
	}

	jwk := &jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     ID,
		Algorithm: alg,
		Use:       "sig",
	}

	if !jwk.Valid() {
		return nil, errors.New("invalid JWK")
	}

	return jwk, nil
}

func (p *oidcTestProvider) discoveryDocument(w http.ResponseWriter, r *http.Request) {
	buf := &bytes.Buffer{}
	err := discoTmpl.Execute(buf, p.Issuer())
	if err != nil {
		panic(err)
	}
	w.WriteHeader(http.StatusOK)
	io.Copy(w, buf)
}

func (p *oidcTestProvider) auth(w http.ResponseWriter, r *http.Request) {
	require.Equal(p.t, p.clientID, r.URL.Query().Get("client_id"))
	require.Equal(p.t, "http://example.com/oauth-callback", r.URL.Query().Get("redirect_uri"))
	require.Equal(p.t, "code", r.URL.Query().Get("response_type"))
	require.Equal(p.t, "openid profile email", r.URL.Query().Get("scope"))
	require.True(p.t, r.URL.Query().Get("state") != "")

	v := url.Values{}
	v.Set("code", "code")
	v.Set("state", r.URL.Query().Get("state"))
	w.Header().Set("Location", fmt.Sprintf("%s?%s", r.URL.Query().Get("redirect_uri"), v.Encode()))
	w.WriteHeader(http.StatusSeeOther)
}

func (p *oidcTestProvider) makeToken(r *http.Request, id, subject, issuer, audience, keyID string, privateKey *rsa.PrivateKey) (*tokenResponse, error) {
	now := time.Now()
	expPeriod := time.Hour * 10
	exp := now.Add(expPeriod)

	claims := &jwt.Claims{
		ID:        id,
		Subject:   subject,
		Issuer:    issuer,
		NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Minute)),
		Expiry:    jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		Audience:  jwt.Audience{audience},
	}

	if p.tokenMinter != nil {
		return p.tokenMinter(r, claims)
	} else {
		builder := jwt.Signed(p.idSigner)

		builder = builder.Claims(claims)

		token, err := builder.CompactSerialize()
		if err != nil {
			panic(err)
		}

		return &tokenResponse{
			IDToken:     token,
			AccessToken: "XXXXXX-magic",
			TokenType:   "Bearer",
			ExpiresIn:   int(expPeriod.Seconds()),
		}, nil

	}
}

func (p *oidcTestProvider) token(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	require.NoError(p.t, err)

	clientID, clientSecret, err := parseTokenRequestClientIDAndSecret(r)
	require.NoError(p.t, err)

	require.Equal(p.t, p.clientID, clientID)
	require.Equal(p.t, p.clientSecret, clientSecret)
	require.Equal(p.t, "code", r.Form.Get("code"))
	require.Equal(p.t, "http://example.com/oauth-callback", r.Form.Get("redirect_uri"))
	require.Equal(p.t, "authorization_code", r.Form.Get("grant_type"))

	aud := r.Form.Get("resource")
	if aud == "" {
		aud = p.server.URL
	}
	token, err := p.makeToken(r, "id", "subject", aud, p.clientID, p.privateKeyID, p.privateKey)
	require.NoError(p.t, err)

	respBytes, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

func (p *oidcTestProvider) certs(w http.ResponseWriter, r *http.Request) {
	ks := &jose.JSONWebKeySet{}

	pubkey := p.privateKey.Public()
	jwk, err := makeJSONWebKey(p.privateKeyID, pubkey)
	if err != nil {
		panic(err)
	}
	ks.Keys = append(ks.Keys, *jwk)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	jwk2, err := makeJSONWebKey("key2", privKey.Public())
	if err != nil {
		panic(err)
	}
	ks.Keys = append(ks.Keys, *jwk2)

	s, err := json.Marshal(ks)
	if err != nil {
		panic(err)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(s)
}

func (p *oidcTestProvider) oidcProviderHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			p.discoveryDocument(w, r)
			return
		case "/v1/oauth/auth":
			p.auth(w, r)
			return
		case "/v1/oauth/token":
			p.token(w, r)
			return
		case "/v1/oauth/certs":
			p.certs(w, r)
			return
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (p *oidcTestProvider) Issuer() string {
	return p.server.URL
}

func (p *oidcTestProvider) Start() {
	p.server.Start()
}

func (p *oidcTestProvider) Close() {
	p.server.Close()
}

func newOIDCTestProvider(t *testing.T, clientID string, clientSecret string) *oidcTestProvider {
	keyID := "key1"
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privKey,
	}

	idSigner, err := jose.NewSigner(signingKey, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyID,
		},
	})
	if err != nil {
		panic(err)
	}

	atSigner, err := jose.NewSigner(signingKey, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid":           keyID,
		},
	})
	if err != nil {
		panic(err)
	}
	p := &oidcTestProvider{
		t: t,

		clientID:     clientID,
		clientSecret: clientSecret,

		privateKeyID: keyID,
		privateKey:   privKey,
		signingKey:   signingKey,
		idSigner:     idSigner,
		atSigner:     atSigner,
	}

	p.server = httptest.NewUnstartedServer(p.oidcProviderHandler())

	return p
}
