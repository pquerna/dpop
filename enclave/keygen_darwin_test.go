package enclave

import (
	"testing"
	"time"

	"github.com/ScaleFT/xjwt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	appName = "dpop-demo-encalve-test"
)

func TestKeygen(t *testing.T) {
	a := Available()
	t.Logf("Enclave Available = %v", a)
	kp, err := generate_keypair(appName, "PQ: DPOP Test (KEY:XXXXXX)", a, true)
	if err != nil {
		t.Logf("generate_keypair failed: %v\n", err)
		t.FailNow()
		return
	}

	ln, err := List(appName)
	if err != nil {
		t.Logf("List failed: %v\n", err)
		t.FailNow()
		return
	}
	t.Logf("List found keys: %v\n", ln)

	t.Logf("generate_keypair: ID=%s LABEL=%s\n", kp.ID(), kp.Label())
	op := cryptosigner.Opaque(kp)
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": kp.ID(),
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: op}, opts)
	if err != nil {
		t.Logf("jose.NewSigner failed: %v\n", err)
		t.FailNow()
		return
	}

	now := time.Now()
	expPeriod := time.Hour * 10
	exp := now.Add(expPeriod)

	claims := &jwt.Claims{
		ID:        "123455",
		Subject:   "joe",
		Issuer:    "https://example.com",
		NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Minute)),
		Expiry:    jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		Audience:  jwt.Audience{"https://example.io"},
	}

	builder := jwt.Signed(signer)

	builder = builder.Claims(claims)

	token, err := builder.CompactSerialize()
	if err != nil {
		t.Logf("CompactSerialize failed: %v\n", err)
		t.FailNow()
		return
	}

	t.Logf("JWT: %s\n", token)

	vcnf := xjwt.VerifyConfig{KeySet: &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key: kp.Public(),
				//Algorithm: jose.ES256,
			},
		},
	}}
	c, err := xjwt.Verify([]byte(token), vcnf)
	if err != nil {
		t.Logf("xjwt.Verify failed: %v\n", err)
		t.FailNow()
		return
	}
	t.Logf("Validated Claims: %v", c)
}
