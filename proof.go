package dpop

import (
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Proof interface {
	// ForRequest annotates an HTTP Request with a DPoP-Proof header.
	ForRequest(r *http.Request, extraClaims interface{}) error
}

type proofer struct {
	signingKey jose.SigningKey
	signer     jose.Signer
	now        func() time.Time
}

// NewProof creates a Proof that can generate DPoP-Proof headers for a request to a resource server.
func NewProof(key jose.SigningKey) (Proof, error) {
	signer, err := jose.NewSigner(key, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: joseProof,
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

	r.Header.Set(headerProof, token)
	return nil
}
