package dpop

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/ScaleFT/xjwt"
	"golang.org/x/xerrors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// BindingValidator validates a DPoP-Binding header.
type BindingValidator struct {
	Now func() time.Time
}

var (
	ErrBindingMissing          = errors.New("dpop: HTTP Header '" + headerBinding + "' not present in request")
	ErrBindingMalformedHeader  = errors.New(`dpop: HTTP Header '` + headerBinding + `' contained a malformed JWT header`)
	ErrBindingMalformedClaim   = errors.New(`dpop: HTTP Header '` + headerBinding + `' contained a malformed JWT claim`)
	ErrBindingInvalidSignature = errors.New(`dpop: HTTP Header '` + headerBinding + `' contained an invalid JWT`)
)

// BindingClaims are common claims in the DPoP-Binding JWT.
type BindingClaims struct {
	jwt.Claims
	HTTPMethod string                     `json:"http_method,omitempty"`
	HTTPUri    string                     `json:"http_uri,omitempty"`
	ClientId   string                     `json:"client_id,omitempty"`
	Cnf        map[string]jose.JSONWebKey `json:"cnf,omitempty"`
}

// Validate parses and performs a PARTIAL validation of the DPoP Binding JWT.
//
// Callers MUST do additional validation for their use case of:
//
//	BindingClaims.iss: Matches your expected Issuer
//	BindingClaims.aud: Matches your expected Audience(s)
//	BindingClaims.sub: Matches your expected Subject
//	BindingClaims.client_id: Matches your expected Client ID
//	BindingClaims.jti: For replay protection, confirm this JTI has not been used before
//
//  JSONWebKey: Algorithm and key type are acceptable.
//
// If this Client has previously used a DPoP-Binding, you may also wish to restrict the
// JSONWebKey to a previously used value.
//
func (bv *BindingValidator) Validate(req *http.Request) (*BindingClaims, *jose.JSONWebKey, error) {
	/*
	   If the authorization server receives a "DPoP-Binding" header in a
	   token request, the authorization server MUST check that:

	   1.  the header value is a well-formed JWT,

	   2.  all required claims are contained in the JWT,

	   3.  the "typ" field in the header has the correct value,

	   4.  the algorithm in the header of the JWT designates a digital
	       signature algorithm, is not "none", is supported by the
	       application, and is deemed secure,

	   5.  the JWT is signed using the public key contained in the "cnf"
	       claim of the JWT,

	   6.  the "http_method" and "http_uri" claims match the respective
	       values for the HTTP request in which the header was received,

	   7.  the token has not expired, and

	   8.  if replay protection is desired, that a JWT with the same "jti"
	       value has not been received previously.
	*/
	bhdr := req.Header.Get(headerBinding)
	if bhdr == "" {
		return nil, nil, ErrBindingMissing
	}

	bjwt, err := jwt.ParseSigned(bhdr)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: "+headerBinding+" did not contain a valid JWT: %v", err)
	}

	if len(bjwt.Headers) != 1 {
		return nil, nil, xerrors.Errorf("dpop: JWT did not contain one header: %v", ErrBindingMalformedHeader)
	}

	bjwtTyp, ok := bjwt.Headers[0].ExtraHeaders["typ"]
	if !ok {
		return nil, nil, xerrors.Errorf("dpop: JWT missing typ field: %v", ErrBindingMalformedHeader)
	}

	if bjwtTyp != joseBinding {
		return nil, nil, xerrors.Errorf("dpop: JWT typ mismatch: '%s': %v", bjwtTyp, ErrBindingMalformedHeader)
	}

	algo := jose.SignatureAlgorithm(bjwt.Headers[0].Algorithm)
	if !isAllowedAlgo(algo) {
		return nil, nil, xerrors.Errorf("dpop: JWT alg not allowed: '%s': %v", algo, ErrBindingInvalidSignature)
	}

	claims := &BindingClaims{}
	err = bjwt.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: "+headerBinding+" did not contain JWT claims: %v", err)
	}

	if claims.HTTPMethod == "" {
		return nil, nil, xerrors.Errorf("dpop: JWT http_method claim missing: %v", ErrBindingMalformedClaim)
	}

	if claims.HTTPUri == "" {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim missing: %v", ErrBindingMalformedClaim)
	}

	if claims.HTTPMethod != req.Method {
		return nil, nil, xerrors.Errorf("dpop: JWT http_method claim mismatch: '%s' != '%s': %v",
			req.Method, claims.HTTPMethod, ErrBindingMalformedClaim)
	}

	claimUrl, err := url.Parse(claims.HTTPUri)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim invalid: %v: %v", ErrBindingMalformedClaim, err)
	}

	if !sameURI(req, claimUrl) {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim mismatch: '%s' != '%s': %v", req.URL.String(), claimUrl.String(), ErrBindingMalformedClaim)
	}

	if claims.ClientId == "" {
		return nil, nil, xerrors.Errorf("dpop: JWT client_id claim missing: %v", ErrBindingMalformedClaim)
	}

	if claims.Cnf == nil {
		return nil, nil, xerrors.Errorf("dpop: cnf claim missing or empty: %v", ErrBindingMalformedClaim)
	}

	cnfClaim, ok := claims.Cnf[jwtCnfJWK]
	if !ok {
		return nil, nil, xerrors.Errorf("dpop: cnf claim missing dpop+jwk entry: %v", ErrBindingMalformedClaim)
	}

	if !cnfClaim.Valid() {
		return nil, nil, xerrors.Errorf("dpop: cnf claim was not valid: %v", ErrBindingMalformedClaim)
	}

	if !cnfClaim.IsPublic() {
		return nil, nil, xerrors.Errorf("dpop: cnf claim was not a public key: %v", ErrBindingMalformedClaim)
	}

	vjwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			cnfClaim,
		},
	}

	vc := xjwt.VerifyConfig{
		Now:    bv.Now,
		KeySet: vjwks,
	}

	_, err = xjwt.VerifyRaw([]byte(bhdr), vc)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: JWT validation failed: %v", err)
	}
	return claims, &cnfClaim, nil
}

func sameURI(r *http.Request, b *url.URL) bool {
	/* TODO(pquerna): this needs to be improved
	/*
	   o  "http_uri": The HTTP URI used for the request, without query and
	      fragment parts (REQUIRED).
	*/
	if r.Host != b.Host {
		return false
	}

	if r.URL.Path != b.Path {
		return false
	}

	return true
}

var validSignatureAlgorithm = []jose.SignatureAlgorithm{
	jose.RS256, // RSASSA-PKCS-v1.5 using SHA-256
	jose.RS384, // RSASSA-PKCS-v1.5 using SHA-384
	jose.RS512, // RSASSA-PKCS-v1.5 using SHA-512
	jose.ES256, // ECDSA using P-256 and SHA-256
	jose.ES384, // ECDSA using P-384 and SHA-384
	jose.ES512, // ECDSA using P-521 and SHA-512
	jose.PS256, // RSASSA-PSS using SHA256 and MGF1-SHA256
	jose.PS384, // RSASSA-PSS using SHA384 and MGF1-SHA384
	jose.PS512, // RSASSA-PSS using SHA512 and MGF1-SHA512
	jose.EdDSA, // EdDSA using Ed25519
}

func isAllowedAlgo(in jose.SignatureAlgorithm) bool {
	for _, validAlgo := range validSignatureAlgorithm {
		if in == validAlgo {
			return true
		}
	}
	return false
}
