package dpop

import (
	"context"
	"encoding/json"
	"golang.org/x/xerrors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type TokenExchange struct {
	// Config for the OAuth exchange.
	Config *oauth2.Config
	// Binder provides the HTTP DPoP  header for this exchange.
	Proof Proof
	// Client optionally overrides the HTTP Client to use for the Exchange. If nil, http.DefaultClient is used
	Client *http.Client
}

// Exchange wraps the process of creating an OAuth Token exchange with a DPoP header.
func (be *TokenExchange) Exchange(ctx context.Context, code string, extra url.Values) (*oauth2.Token, error) {
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

	err = be.Proof.ForRequest(req, map[string]interface{}{})

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
		return nil, xerrors.Errorf("dpop: Invalid response code for Token Request: %d", resp.StatusCode)
	}

	rv := &oauth2.Token{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		// TODO(pquerna): custom error types
		return nil, err
	}

	return rv, nil
}
