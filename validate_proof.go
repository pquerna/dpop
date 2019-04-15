package dpop

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/ScaleFT/xjwt"
	"golang.org/x/xerrors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ProofValidator validates DPoP-Proof headers on a resource server request.
type ProofValidator struct {
	xjwt.VerifyConfig
}

var (
	ErrProofMissing          = errors.New("dpop: HTTP Header '" + headerProof + "' not present in request")
	ErrProofMalformedHeader  = errors.New(`dpop: HTTP Header '` + headerProof + `' contained a malformed JWT header`)
	ErrProofMalformedClaim   = errors.New(`dpop: HTTP Header '` + headerProof + `' contained a malformed JWT claim`)
	ErrProofInvalidSignature = errors.New(`dpop: HTTP Header '` + headerProof + `' contained an invalid JWT`)
)

// ProofClaims are common claims in the DPoP-Proof JWT.
type ProofClaims struct {
	jwt.Claims
	HTTPMethod string `json:"http_method,omitempty"`
	HTTPUri    string `json:"http_uri,omitempty"`
}

// Validate parses and performs a PARTIAL validation of the DPoP Proof JWT
//
// Callers MUST do additional validation for their use case of:
//
//	ProofClaims.jti: For replay protection, confirm this JTI has not been used before
//
func (pv *ProofValidator) Validate(req *http.Request, atBinding jose.JSONWebKey) (*ProofClaims, []byte, error) {
	/*
	   1.  a header "DPoP-Proof" was received in the HTTP request,

	   2.  the header's value is a well-formed DPoP Proof JWT,

	   3.  all required claims are contained in the JWT,

	   4.  the algorithm in the header of the JWT designates a digital
	       signature algorithm, is not "none", is supported by the
	       application, and is deemed secure,

	   5.  the JWT is signed using the public key to which the access token
	       was bound,

	   6.  the "typ" field in the header has the correct value,

	   7.  the "http_method" and "http_uri" claims match the respective
	       values for the HTTP request in which the header was received,

	   8.  the token has not expired, and

	   9.  if replay protection is desired, that a JWT with the same "jti"
	       value has not been received previously.
	*/

	phdr := req.Header.Get(headerProof)
	if phdr == "" {
		return nil, nil, ErrProofMissing
	}

	pjwt, err := jwt.ParseSigned(phdr)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: "+headerProof+" did not contain a valid JWT: %v", err)
	}

	if len(pjwt.Headers) != 1 {
		return nil, nil, xerrors.Errorf("dpop: JWT did not contain one header: %v", ErrProofMalformedHeader)
	}

	pjwtTyp, ok := pjwt.Headers[0].ExtraHeaders["typ"]
	if !ok {
		return nil, nil, xerrors.Errorf("dpop: JWT missing typ field: %v", ErrProofMalformedHeader)
	}

	if pjwtTyp != joseProof {
		return nil, nil, xerrors.Errorf("dpop: JWT typ mismatch: '%s': %v", pjwtTyp, ErrProofMalformedHeader)
	}

	algo := jose.SignatureAlgorithm(pjwt.Headers[0].Algorithm)
	if !isAllowedAlgo(algo) {
		return nil, nil, xerrors.Errorf("dpop: JWT alg not allowed: '%s': %v", algo, ErrProofInvalidSignature)
	}

	claims := &ProofClaims{}
	err = pjwt.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: "+headerProof+" did not contain JWT claims: %v", err)
	}

	if claims.HTTPMethod == "" {
		return nil, nil, xerrors.Errorf("dpop: JWT http_method claim missing: %v", ErrProofMalformedClaim)
	}

	if claims.HTTPUri == "" {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim missing: %v", ErrProofMalformedClaim)
	}

	if claims.HTTPMethod != req.Method {
		return nil, nil, xerrors.Errorf("dpop: JWT http_method claim mismatch: '%s' != '%s': %v",
			req.Method, claims.HTTPMethod, ErrProofMalformedClaim)
	}

	claimUrl, err := url.Parse(claims.HTTPUri)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim invalid: %v: %v", ErrProofMalformedClaim, err)
	}

	if !sameURI(req, claimUrl) {
		return nil, nil, xerrors.Errorf("dpop: JWT http_uri claim mismatch: '%s' != '%s': %v", req.URL.String(), claimUrl.String(), ErrProofMalformedClaim)
	}

	vjwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			atBinding,
		},
	}

	vc := pv.VerifyConfig
	vc.KeySet = vjwks

	rawClaims, err := xjwt.VerifyRaw([]byte(phdr), vc)
	if err != nil {
		return nil, nil, xerrors.Errorf("dpop: JWT validation failed: %v", err)
	}

	return claims, rawClaims, nil
}
