package dpop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Binding interface {
	// ForRequest annotates an HTTP Request with a DPoP-Binding header.
	ForRequest(r *http.Request, extraClaims interface{}) error
}

type binder struct {
	signingKey jose.SigningKey
	publicKey  jose.JSONWebKey
	signer     jose.Signer
	now        func() time.Time
}

// NewBinding creates a Binding that can generate DPoP-Binding headers for an OAuth Token exchange.
func NewBinding(key jose.SigningKey) (Binding, error) {
	signer, err := jose.NewSigner(key, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: joseBinding,
		},
	})
	if err != nil {
		return nil, err
	}
	wk := jose.JSONWebKey{
		Key:   key.Key,
		KeyID: "",
	}
	return &binder{
		signingKey: key,
		signer:     signer,
		publicKey:  wk.Public(),
		now:        time.Now,
	}, nil
}

const (
	bindingExp = time.Minute * 5
	bindingNbf = -2 * time.Minute
)

func (b *binder) ForRequest(r *http.Request, extraClaims interface{}) error {
	builder := jwt.Signed(b.signer)

	now := b.now()
	exp := now.Add(bindingExp)
	jti := randCryptoString(16)

	claims := &jwt.Claims{
		ID:        jti,
		NotBefore: jwt.NewNumericDate(now.Add(bindingNbf)),
		Expiry:    jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	builder = builder.Claims(claims)
	builder = builder.Claims(map[string]interface{}{
		"cnf": map[string]interface{}{
			jwtCnfJWK: b.publicKey,
		},
		"http_method": r.Method,
		"http_uri":    r.URL.String(),
	})

	if extraClaims != nil {
		builder = builder.Claims(extraClaims)
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return err
	}

	r.Header.Set(headerBinding, token)

	return nil
}

type BindingExchange struct {
	// Config for the OAuth exchange.
	Config *oauth2.Config
	// Binder provides the HTTP DPoP-Binding header for this exchange.
	Binder Binding
	// Client optionally overrides the HTTP Client to use for the Exchange. If nil, http.DefaultClient is used
	Client *http.Client
}

// Exchange wraps the process of creating an OAuth Token exchange with a DPoP-Binding header.
func (be *BindingExchange) Exchange(ctx context.Context, code string, extra url.Values) (*oauth2.Token, error) {
	var v url.Values
	if extra != nil {
		v = cloneURLValues(extra)
	} else {
		v = make(url.Values)
	}

	v.Set("grant_type", "authorization_code")
	v.Set("code", code)

	if be.Config.RedirectURL != "" {
		v.Set("redirect_uri", be.Config.RedirectURL)
	}

	req, err := newTokenRequest(be.Config.Endpoint.TokenURL, be.Config.ClientID, be.Config.ClientSecret, v, oauth2.AuthStyleInParams)
	if err != nil {
		return nil, err
	}

	err = be.Binder.ForRequest(req, map[string]interface{}{
		"client_id": be.Config.ClientID,
	})

	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	client := be.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// TODO(pquerna): custom error types
		return nil, fmt.Errorf("dpop: Invalid response code for Token Request: %d", resp.StatusCode)
	}

	rv := &oauth2.Token{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		// TODO(pquerna): custom error types
		return nil, err
	}

	return rv, nil
}
