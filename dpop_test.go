package dpop

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
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
		binding := req.Header.Get(headerBinding)
		require.NotEmpty(t, binding)

		dpopBindingHeader = req.Header.Get(headerBinding)
		bv := &BindingValidator{}
		claims, bindingCnf, err := bv.Validate(req)
		if err != nil {
			return nil, err
		}

		if claims.ClientId != clientId {
			return nil, fmt.Errorf("Invalid client_id")
		}

		builder := jwt.Signed(provider.idSigner)
		builder = builder.Claims(idClaims)
		idToken, err := builder.CompactSerialize()
		if err != nil {
			return nil, err
		}

		atClaims := *idClaims
		atClaims.Subject = "x1234"

		builder = jwt.Signed(provider.atSigner).
			Claims(&atClaims).
			Claims(map[string]interface{}{
				"client_id": clientId,
				"scopes":    "openid example.com/api",
				"cnf": map[string]interface{}{
					jwtCnfJWK: bindingCnf,
				},
			})
		accessToken, err := builder.CompactSerialize()
		if err != nil {
			return nil, err
		}

		return &tokenResponse{
			IDToken:     idToken,
			AccessToken: accessToken,
			TokenType:   "Bearer+DPoP",
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
	b, err := NewBinding(sk)
	require.NoError(t, err)

	be := BindingExchange{
		Binder: b,
		Config: config,
	}

	token, err := be.Exchange(ctx, "code",
		url.Values{
			"resource": {"https://example.com/api"},
		},
	)
	require.NoError(t, err)
	require.Equal(t, accesTokenType, token.TokenType)

	proofer, err := NewProof(sk)
	require.NoError(t, err)

	rsReq, err := http.NewRequest("GET", "https://example.com/api/magic", nil)
	require.NoError(t, err)
	rsReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

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

	atCnf := atc.Cnf[jwtCnfJWK]
	require.True(t, atCnf.IsPublic())
	require.Equal(t, atCnf.Key, skWebKey.Public().Key)

	_, _, err = pv.Validate(rsReq, atCnf)
	require.NoError(t, err)

	t.Logf("DPoP-Binding JWT: %s", dpopBindingHeader)
	t.Logf("DPoP-Proof JWT: %s", rsReq.Header.Get(headerProof))
}

type atClaims struct {
	Cnf map[string]jose.JSONWebKey `json:"cnf,omitempty"`
}
