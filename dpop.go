package dpop

const (
	// 10.1.  OAuth Access Token Type Registration
	accesTokenType = `Bearer+DPoP`

	// 10.2.  JWT Confirmation Methods Registration
	jwtCnfJWK = `dpop+jwk`

	// 10.3.  JSON Web Signature and Encryption Type Values Registration
	joseProof   = `dpop_proof+jwt`
	joseBinding = `dpop_binding+jwt`
)

const (
	headerBinding = `DPoP-Binding`
	headerProof   = `DPoP-Proof`
)

const (
	// 7.  IANA Considerations
	//
	//   [[TODO: MIME type registration for at+jwt ]]
	jwtHeaderTypAT = "at+JWT"
)
