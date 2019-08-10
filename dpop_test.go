package dpop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"net/http"
	"net/url"
	"testing"

	"github.com/ScaleFT/xjwt"
	"github.com/coreos/go-oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestExchange(t *testing.T) {
	var dpopBindingHeader string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientId := "clientid"
	provider := newOIDCTestProvider(t, clientId, "clientsecret")

	provider.tokenMinter = func(req *http.Request, idClaims *jwt.Claims) (*tokenResponse, error) {
		binding := req.Header.Get(httpHeader)
		require.NotEmpty(t, binding)

		dpopBindingHeader = req.Header.Get(httpHeader)
		bv := &ProofValidator{}
		claims, rawClaims, bindingCnf, err := bv.ValidateTokenRequest(req)
		if err != nil {
			return nil, err
		}
		_ = claims
		_ = rawClaims

		builder := jwt.Signed(provider.idSigner)
		builder = builder.Claims(idClaims)
		idToken, err := builder.CompactSerialize()
		if err != nil {
			return nil, err
		}

		atClaims := *idClaims
		atClaims.Subject = "x1234"

		tb, err := bindingCnf.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, err
		}

		builder = jwt.Signed(provider.atSigner).
			Claims(&atClaims).
			Claims(map[string]interface{}{
				"client_id": clientId,
				"scopes":    "openid example.com/api",
				"cnf": map[string]interface{}{
					jktS256: base64.URLEncoding.EncodeToString(tb),
				},
			})
		accessToken, err := builder.CompactSerialize()
		if err != nil {
			return nil, err
		}

		return &tokenResponse{
			IDToken:     idToken,
			AccessToken: accessToken,
			TokenType:   "DPoP",
			ExpiresIn:   300,
		}, nil
	}

	provider.Start()
	defer provider.Close()

	xoidc, err := oidc.NewProvider(ctx, provider.Issuer())
	require.NoError(t, err)

	config := &oauth2.Config{
		ClientID:     "clientid",
		ClientSecret: "clientsecret",
		Endpoint:     xoidc.Endpoint(),
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURL:  "http://example.com/oauth-callback",
	}
	sk := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}
	b, err := New(sk)
	require.NoError(t, err)

	be := TokenExchange{
		Proof: b,
		Config: config,
	}

	token, err := be.Exchange(ctx, "code",
		url.Values{
			"resource": {"https://example.com/api"},
		},
	)
	require.NoError(t, err)
	require.Equal(t, accessTokenType, token.TokenType)

	proofer, err := New(sk)
	require.NoError(t, err)

	rsReq, err := http.NewRequest("GET", "https://example.com/api/magic", nil)
	require.NoError(t, err)
	rsReq.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))

	err = proofer.ForRequest(rsReq, nil)
	require.NoError(t, err)

	pv := &ProofValidator{}
	skWebKey := jose.JSONWebKey{Key: privateKey}

	atClaimsRaw, err := xjwt.VerifyRaw([]byte(token.AccessToken), xjwt.VerifyConfig{
		KeySet: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:   provider.privateKey.Public(),
					KeyID: "key1",
				},
			},
		},
	})
	require.NoError(t, err)

	atc := &atClaims{}
	err = json.Unmarshal(atClaimsRaw, atc)
	require.NoError(t, err)

	atCnf := atc.Cnf[jktS256]
	require.NotEmpty(t, atCnf)
	pubkey := skWebKey.Public()
	tb, err := pubkey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, atCnf, base64.URLEncoding.EncodeToString(tb))
	spew.Dump(atCnf)
	_, _,_, err = pv.ValidateResourceAccess(rsReq, atCnf)
	require.NoError(t, err)

	t.Logf("DPoP Token Exchange JWT: %s", dpopBindingHeader)
	t.Logf("DPoP Resource Access JWT: %s", rsReq.Header.Get(httpHeader))
}

type atClaims struct {
	Cnf map[string]string `json:"cnf,omitempty"`
}
