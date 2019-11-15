package dpop

import (
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Proof interface {
	// ForRequest annotates an HTTP Request with a DPoP header.
	ForRequest(r *http.Request, extraClaims interface{}) error
}

type proofer struct {
	signingKey jose.SigningKey
	signer     jose.Signer
	now        func() time.Time
}

// New creates a DPoP Proof that can generate DPoP headers for a request.
func New(key jose.SigningKey) (Proof, error) {
	signer, err := jose.NewSigner(key, &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: typDPOP,
		},
	})
	if err != nil {
		return nil, err
	}
	return &proofer{
		signingKey: key,
		signer:     signer,
		now:        time.Now,
	}, nil
}

const (
	proofExp = time.Minute * 5
	proofNbf = -2 * time.Minute
)

func mungedURL(input *url.URL) *url.URL {
	rv := new(url.URL)
	*rv = *input
	rv.Fragment = ""
	rv.RawQuery = ""
	rv.ForceQuery = false
	return rv
}

func (p *proofer) ForRequest(r *http.Request, extraClaims interface{}) error {
	builder := jwt.Signed(p.signer)

	now := p.now()
	exp := now.Add(proofExp)
	jti := randCryptoString(16)

	claims := &jwt.Claims{
		ID:        jti,
		NotBefore: jwt.NewNumericDate(now.Add(proofNbf)),
		Expiry:    jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	builder = builder.Claims(claims)
	builder = builder.Claims(map[string]interface{}{
		claimHTTPMethod: r.Method,
		claimHTTPURL:    mungedURL(r.URL).String(),
	})
	if extraClaims != nil {
		builder = builder.Claims(extraClaims)
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return err
	}

	r.Header.Set(httpHeader, token)
	return nil
}
