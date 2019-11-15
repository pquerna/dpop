package dpop

import (
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ScaleFT/xjwt"
	"golang.org/x/xerrors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// ProofValidator validates DPoP proof headers
type Validator struct {
	xjwt.VerifyConfig
}

var (
	ErrProofMissing          = errors.New("dpop: HTTP Header '" + httpHeader + "' not present in request")
	ErrProofMalformedHeader  = errors.New(`dpop: HTTP Header '` + httpHeader + `' contained a malformed JWT header`)
	ErrProofMalformedClaim   = errors.New(`dpop: HTTP Header '` + httpHeader + `' contained a malformed JWT claim`)
	ErrProofInvalidSignature = errors.New(`dpop: HTTP Header '` + httpHeader + `' contained an invalid JWT`)
)

// ProofClaims are common claims in the DPoP proof JWT.
type ProofClaims struct {
	jwt.Claims
	HTTPMethod string `json:"htm,omitempty"`
	HTTPUri    string `json:"htu,omitempty"`
}

// ValidateTokenRequest parses and performs a PARTIAL validation of the DPoP proof JWT.
//
// It returns common proof claims, raw claims, and the public JWK used to sign the proof.
//
// Callers MUST do additional validation for their use case of:
//
//	ProofClaims.JTI: For replay protection, confirm this JTI has not been used before:
//		   Within a reasonable consideration of accuracy and resource
//	       utilization, a JWT with the same "jti" value has not been
//	       received previously (see Section 9.1).
//
//  JSONWebKey: The caller must calculate the JWK SHA-256 Thumbprint, encoding it using base64url, and
//  	embed it in any Access Tokens issued or make it available in the introspection request:
//			tb, err := key.Thumbprint(crypto.SHA256)
//  		cnfThumbprint := base64.URLEncoding.EncodeToString(tb)
//
//  JSONWebKey: Algorithm and key type are acceptable.
//
// If this Client has previously used a DPoP binding at Token request, you may also wish to restrict the
// JSONWebKey to a previously used value.
//
func (pv *Validator) ValidateTokenRequest(req *http.Request) (*ProofClaims, []byte, *jose.JSONWebKey, error) {
	pc, raw, k, err := pv.validate(req)
	if err != nil {
		return nil, nil, nil, err
	}

	return pc, raw, k, nil
}

// ValidateResourceAccess parses and performs a PARTIAL validation of the DPoP proof JWT.
//
// It returns common proof claims, raw claims, and the public JWK used to sign the proof.
//
// keyFingerprint is the "jkt#S256" cnf claim from a JWT based Access Token or from an introspection response.
//
// Callers MUST do additional validation for their use case of:
//
//	ProofClaims.JTI: For replay protection, confirm this JTI has not been used before:
//		   Within a reasonable consideration of accuracy and resource
//	       utilization, a JWT with the same "jti" value has not been
//	       received previously (see Section 9.1).
//
func (pv *Validator) ValidateResourceAccess(req *http.Request, keyFingerprint string) (*ProofClaims, []byte, *jose.JSONWebKey, error) {
	pc, raw, k, err := pv.validate(req)
	if err != nil {
		return nil, nil, nil, err
	}

	jwkHash, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: can't thumbprint jwk: %v", err)
	}
	atHash, err := base64.URLEncoding.DecodeString(keyFingerprint)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: access token's key hash failed to base64 decode: %v", err)
	}

	if subtle.ConstantTimeCompare(jwkHash, atHash) == 0 {
		d := base64.URLEncoding.EncodeToString(jwkHash)
		return nil, nil, nil, xerrors.Errorf("dpop: key mismatch: expected='%s' access_token_hash='%s'", d, keyFingerprint)
	}

	return pc, raw, k, nil
}

func (pv *Validator) validate(req *http.Request) (*ProofClaims, []byte, *jose.JSONWebKey, error) {
	/*
		4.2.  Checking DPoP Proofs

		   To check if a string that was received as part of an HTTP Request is
		   a valid DPoP proof, the receiving server MUST ensure that

		   1.  the string value is a well-formed JWT,

		   2.  all required claims are contained in the JWT,

		   3.  the "typ" field in the header has the value "dpop+jwt",

		   4.  the algorithm in the header of the JWT indicates an asymmetric
		       digital signature algorithm, is not "none", is supported by the
		       application, and is deemed secure,

		   5.  that the JWT is signed using the public key contained in the
		       "jwk" header of the JWT,

		   6.  the "htm" claim matches the respective value for the HTTP
		       request in which the JWT was received (case-insensitive),

		   7.  the "htu" claims matches the respective value for the HTTP
		       request in which the JWT was received, ignoring any query and
		       fragment parts,

		   8.  the token was issued within an acceptable timeframe (see
		       Section 9.1), and

		   9.  that, within a reasonable consideration of accuracy and resource
		       utilization, a JWT with the same "jti" value has not been
		       received previously (see Section 9.1).

		   Servers SHOULD employ Syntax-Based Normalization and Scheme-Based
		   Normalization in accordance with Section 6.2.2. and Section 6.2.3. of
		   [RFC3986] before comparing the "http_uri" claim.
	*/

	phdr := req.Header.Get(httpHeader)
	if phdr == "" {
		return nil, nil, nil, ErrProofMissing
	}

	pjwt, err := jwt.ParseSigned(phdr)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: "+httpHeader+" did not contain a valid JWT: %v", err)
	}

	if len(pjwt.Headers) != 1 {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT did not contain one header: %v", ErrProofMalformedHeader)
	}

	pjwtTyp, ok := pjwt.Headers[0].ExtraHeaders["typ"]
	if !ok {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT missing typ field in header: %v", ErrProofMalformedHeader)
	}

	if pjwtTyp != typDPOP {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT typ mismatch in header: '%s': %v", pjwtTyp, ErrProofMalformedHeader)
	}

	pjwk := pjwt.Headers[0].JSONWebKey
	if pjwk == nil {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT missing jwk field in header: %v", ErrProofMalformedHeader)
	}
	if !pjwk.IsPublic() {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT jwk field in header must be public key: %v", ErrProofMalformedHeader)
	}

	algo := jose.SignatureAlgorithm(pjwt.Headers[0].Algorithm)
	if !isAllowedAlgo(algo) {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT alg not allowed: '%s': %v", algo, ErrProofInvalidSignature)
	}

	claims := &ProofClaims{}
	err = pjwt.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: "+httpHeader+" did not contain JWT claims: %v", err)
	}

	if claims.HTTPMethod == "" {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_method claim missing: %v", ErrProofMalformedClaim)
	}

	if claims.HTTPUri == "" {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_uri claim missing: %v", ErrProofMalformedClaim)
	}

	if strings.ToUpper(claims.HTTPMethod) != strings.ToUpper(req.Method) {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_method claim mismatch: expected='%s' received='%s': %v",
			req.Method, claims.HTTPMethod, ErrProofMalformedClaim)
	}

	claimUrl, err := url.Parse(claims.HTTPUri)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_uri claim invalid: %v: %v", ErrProofMalformedClaim, err)
	}

	// From the req.URL docs:
	//
	// For server requests, the URL is parsed from the URI
	// supplied on the Request-Line as stored in RequestURI.  For
	// most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)
	murl := mungedURL(req.URL)
	if murl.Path != claimUrl.Path {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_uri claim mismatch in path: expected='%s' received='%s': %v", murl.String(), claimUrl.String(), ErrProofMalformedClaim)
	}
	if req.Host != claimUrl.Host {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT http_uri claim mismatch in hostname: expected='%s' received='%s': %v", req.Host, claimUrl.Host, ErrProofMalformedClaim)
	}

	// if claimUrl.Scheme != "https" {
	//	return nil, nil, nil, xerrors.Errorf("dpop: JWT http_uri claim mismatch in scheme: expected='https' received='%s': %v",  claimUrl.Scheme, ErrProofMalformedClaim)
	//}

	var now time.Time
	if pv.Now == nil {
		now = time.Now()
	} else {
		now = pv.Now()
	}
	if claims.IssuedAt == nil {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT iat claim missing: %v", ErrProofMalformedClaim)
	}

	iat := claims.IssuedAt.Time()
	d := absDuration(now.Sub(iat))

	if d > time.Minute*5 {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT iat claim is more than 5 minutes from now: now='%s' iat='%s' %v", now.String(), iat.String(), ErrProofMalformedClaim)
	}

	vjwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			pjwk.Public(),
		},
	}

	vc := pv.VerifyConfig
	vc.KeySet = vjwks

	rawClaims, err := xjwt.VerifyRaw([]byte(phdr), vc)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("dpop: JWT validation failed: %v", err)
	}

	return claims, rawClaims, pjwk, nil
}

func absDuration(n time.Duration) time.Duration {
	y := n >> 63
	return (n ^ y) - y
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
